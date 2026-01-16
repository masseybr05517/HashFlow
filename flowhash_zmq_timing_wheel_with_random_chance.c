/*********************************************************************
 *  flowhash_zmq_timing_wheel.c
 *
 *  • Tracks first 40 packets of every bi-directional flow (5-tuple key)
 *  • TCP flows flush on FIN+FIN; UDP via O(1) timing-wheel (30 s idle)
 *  • Completed flows are buffered, encoded to JSON, and pushed over
 *    ZeroMQ in batches (PUSH socket bound to "ipc:///tmp/flowpipe").
 *
 *  Build:
 *    gcc flowhash_zmq_timing_wheel.c -std=c11 -O2 -Wall -pthread -lpcap \
 *        $(pkg-config --cflags --libs jansson libzmq) -o flowhash_zmq_timing_wheel
 *********************************************************************/
 #define _DEFAULT_SOURCE
 #define __FAVOR_BSD
 #include <sys/types.h>
 #include <arpa/inet.h>
 #include <inttypes.h>
 #include <jansson.h>
 #include <netinet/if_ether.h>
 #include <netinet/ip.h>
 #include <netinet/tcp.h>
 #include <netinet/udp.h>
 #include <pcap.h>
 #include <pthread.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/time.h>
 #include <time.h>
 #include <zmq.h>
 
 /* ---------- parameters ------------------------------------------- */
 #define TABLE_SIZE (65536 * 2) /* power of 2                         */
 #define FLOW_CAP 40            /* pkts per flow                      */
 #define UDP_IDLE_SEC 30        /* idle timeout for UDP               */
 #define TW_SLOTS 256           /* timing-wheel slots (>= idle + slop)*/
 #define BUF_MAX 64             /* flow buffer for ZMQ sender thread  */
 #define BATCH_SIZE 16          /* flows per JSON batch               */
 #define SHOW_OUTPUT 1          /* set 1 for stderr debug prints      */
 #define WRITE_TO_CSV 0
 
 /* ---------- tiny FNV-1a 32-bit ------------------------------------ */
 static uint32_t fnv1a_32(const char *s) {
   uint32_t h = 0x811c9dc5u;
   while (*s) {
     h ^= (uint8_t)(*s++);
     h *= 0x01000193u;
   }
   return h;
 }
 
 /* ---------- flow key / entry ------------------------------------- */
 typedef struct {
   uint32_t ip1, ip2; /* canonical src/dst order          */
   uint16_t port1, port2;
   uint8_t proto; /* IPPROTO_TCP | IPPROTO_UDP        */
 } flow_key_t;
 
 typedef struct flow_entry {
   int in_use;
   flow_key_t key;
 
   /* original orientation = first-packet perspective */
   uint32_t cli_ip, srv_ip;
   uint16_t cli_port, srv_port;
 
   int is_udp;
   int fin_cli_done, fin_srv_done;
 
   struct timeval ts[FLOW_CAP];
   int32_t len[FLOW_CAP];
   int count;
 
   /* --- timing-wheel bookkeeping --- */
   int tw_next;
   int tw_slot;
 } flow_entry_t;
 
 static flow_entry_t table[TABLE_SIZE] = {0};
 static uint8_t g_evict_mode = 0;      // 0=FCFS, 1=coin
 static uint32_t g_rng = 0x12345678u;  // seed in main

 /* ---------- timing-wheel data ------------------------------------ */
 static int tw_head[TW_SLOTS];
 static time_t tw_now_sec = 0;
 static int tw_now_slot = 0;
 static int tw_initialised = 0;
 static inline int idx_of(flow_entry_t *e) { return (int)(e - table); }
 
 /* ---------- ZMQ batching buffer ---------------------------------- */
 typedef struct {
   flow_entry_t slot;
   int used;
 } buf_item_t;
 
 static buf_item_t flow_buf[BUF_MAX];
 static size_t head = 0, tail = 0, fill = 0;
 static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
 static pthread_cond_t cond_full = PTHREAD_COND_INITIALIZER;
 static pthread_t zmq_thread;
 static int exiting = 0;
 
 /* ================================================================= */
 /*                           Timing-wheel                             */
 /* ================================================================= */
 static void tw_init(time_t start_sec) {
   for (int i = 0; i < TW_SLOTS; ++i) tw_head[i] = -1;
   tw_now_sec = start_sec;
   tw_now_slot = (int)(start_sec % TW_SLOTS);
   tw_initialised = 1;
 }
 
 static void tw_remove(int idx) {
   flow_entry_t *e = &table[idx];
   if (e->tw_slot < 0) return;
 
   int slot = e->tw_slot;
   int cur = tw_head[slot];
   int prev = -1;
   while (cur != -1 && cur != idx) {
     prev = cur;
     cur = table[cur].tw_next;
   }
 
   if (cur == -1) {
     e->tw_slot = e->tw_next = -1;
     return;
   }
   if (prev == -1)
     tw_head[slot] = table[cur].tw_next;
   else
     table[prev].tw_next = table[cur].tw_next;
 
   e->tw_slot = e->tw_next = -1;
 }
 
 static void tw_insert(int idx, time_t exp_sec) {
   flow_entry_t *e = &table[idx];
   if (e->tw_slot >= 0) tw_remove(idx);
 
   int slot = (int)(exp_sec % TW_SLOTS);
   e->tw_slot = slot;
   e->tw_next = tw_head[slot];
   tw_head[slot] = idx;
 }
 
 static void tw_advance(time_t now_sec);
 
 /* ================================================================= */
 /*                       JSON encoding helpers                        */
 /* ================================================================= */
 static json_t *json_from_entry(const flow_entry_t *f) {
   char cli[INET_ADDRSTRLEN], srv[INET_ADDRSTRLEN];
   inet_ntop(AF_INET, &f->cli_ip, cli, sizeof cli);
   inet_ntop(AF_INET, &f->srv_ip, srv, sizeof srv);
 
   json_t *root = json_object();
   json_object_set_new(root, "cli_ip", json_string(cli));
   json_object_set_new(root, "srv_ip", json_string(srv));
   json_object_set_new(root, "cli_port", json_integer(f->cli_port));
   json_object_set_new(root, "srv_port", json_integer(f->srv_port));
   json_object_set_new(root, "proto", json_string(f->is_udp ? "UDP" : "TCP"));
   json_object_set_new(root, "count", json_integer(f->count));
 
   json_t *tsa = json_array(), *lena = json_array();
   double t0 = f->ts[0].tv_sec + f->ts[0].tv_usec / 1e6;
   for (int i = 0; i < f->count; ++i) {
     double t = f->ts[i].tv_sec + f->ts[i].tv_usec / 1e6;
     json_array_append_new(tsa, json_real(t - t0));
     json_array_append_new(lena, json_integer(f->len[i]));
   }
   json_object_set_new(root, "ts", tsa);
   json_object_set_new(root, "len", lena);
   return root;
 }
 
 /* ================================================================= */
 /*                    Buffer / sender-thread logic                    */
 /* ================================================================= */
 static inline void enqueue_flow(const flow_entry_t *src) {
   pthread_mutex_lock(&mtx);
   if (fill == BUF_MAX) {
     tail = (tail + 1) % BUF_MAX;
     fill--;
   } /* drop oldest */
   flow_buf[head].slot = *src;
   flow_buf[head].used = 1;
   head = (head + 1) % BUF_MAX;
   fill++;
   if (fill >= BATCH_SIZE) pthread_cond_signal(&cond_full);
   pthread_mutex_unlock(&mtx);
 }
 
 static void *sender_thread(void *arg) {
   void *ctx = zmq_ctx_new();
   void *sock = zmq_socket(ctx, ZMQ_PUSH);
   zmq_bind(sock, "ipc:///tmp/flowpipe");
 
   while (1) {
     pthread_mutex_lock(&mtx);
     while (fill < BATCH_SIZE && !exiting) pthread_cond_wait(&cond_full, &mtx);
 
     json_t *batch = json_array();
     int sent = 0;
     while (fill && sent < BATCH_SIZE) {
       buf_item_t item = flow_buf[tail];
       tail = (tail + 1) % BUF_MAX;
       fill--;
       sent++;
 
       json_t *obj = json_from_entry(&item.slot);
       json_array_append_new(batch, obj);
     }
     pthread_mutex_unlock(&mtx);
 
     if (json_array_size(batch) > 0) {
       char *txt = json_dumps(batch, JSON_COMPACT);
       zmq_send(sock, txt, strlen(txt), 0);
       free(txt);
     }
     json_decref(batch);
 
     if (exiting && fill == 0) break;
   }
   zmq_close(sock);
   zmq_ctx_term(ctx);
   return NULL;
 }
 
 /* ================================================================= */
 /*                         helper functions                           */
 /* ================================================================= */
 static int compare_key(const flow_key_t *a, const flow_key_t *b) {
   return !(a->ip1 == b->ip1 && a->ip2 == b->ip2 && a->port1 == b->port1 &&
            a->port2 == b->port2 && a->proto == b->proto);
 }
 
 static flow_key_t make_key(uint32_t s_ip, uint32_t d_ip, uint16_t s_pt,
                            uint16_t d_pt, uint8_t proto) {
   flow_key_t k;
   if (ntohl(s_ip) < ntohl(d_ip)) {
     k.ip1 = s_ip;
     k.ip2 = d_ip;
     k.port1 = s_pt;
     k.port2 = d_pt;
   } else if (ntohl(s_ip) > ntohl(d_ip)) {
     k.ip1 = d_ip;
     k.ip2 = s_ip;
     k.port1 = d_pt;
     k.port2 = s_pt;
   } else {
     k.ip1 = s_ip;
     k.ip2 = d_ip;
     if (s_pt > d_pt) {
       uint16_t t = s_pt;
       s_pt = d_pt;
       d_pt = t;
     }
     k.port1 = s_pt;
     k.port2 = d_pt;
   }
   k.proto = proto;
   return k;
 }
 static inline uint32_t rng32(void) {
  g_rng ^= g_rng << 13;
  g_rng ^= g_rng >> 17;
  g_rng ^= g_rng << 5;
  return g_rng;
 }
 static inline int coin50(void) {
  return (int)(rng32() & 1u); // 50/50
 }
 
 static int find_bucket(const flow_key_t *key, uint32_t h, int *found) {
    uint32_t p = h & (TABLE_SIZE - 1);

    if (!table[p].in_use) { *found = 0; return (int)p; }
    if (!compare_key(&table[p].key, key)) { *found = 1; return (int)p; }
 
    // collision
    if (!g_evict_mode) return -1;     // FCFS
    if (!coin50()) return -1;         // coin says "keep incumbent"

    // coin says "evict incumbent": caller will reuse p
    *found = 0;
    return (int)p;
}

static void write_to_csv(flow_entry_t *e)
    {
    if (e->count == FLOW_CAP) {
        char ip_small[INET_ADDRSTRLEN], ip_large[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &e->key.ip1, ip_small, sizeof(ip_small));
        inet_ntop(AF_INET, &e->key.ip2, ip_large, sizeof(ip_large));

        char input_field[256];
        snprintf(input_field, sizeof(input_field), "%s%d%s%d%s",
                ip_small, e->key.port1, ip_large, e->key.port2,
                e->is_udp ? "UDP" : "TCP");

        /* Build the feature vector string.
        Each tuple is (time_offset, signed length) calculated relative
        to the timestamp of the first packet. */
        char feature_vector[4096];
        feature_vector[0] = '\0';
        strcat(feature_vector, "[");
        double ts_0 = e->ts[0].tv_sec + e->ts[0].tv_usec / 1e6;
        char tuple[64];
        for (int i = 0; i < e->count; ++i) {
            double ts = e->ts[i].tv_sec + e->ts[i].tv_usec / 1e6;
            double offset = ts - ts_0;
            if (e->len[i] < 0) {
                offset *= -1;
            }
            snprintf(tuple, sizeof(tuple), "(%.6f, %.1f)", offset, (double)e->len[i]);
            strcat(feature_vector, tuple);
            if (i < e->count - 1)
                strcat(feature_vector, ", ");
        }
        strcat(feature_vector, "]");

        /* Write CSV fields (input, feature vector) to file */
        FILE *f = fopen("flow_output_timing_wheel_zmq.csv", "a");
        if (!f) {
            perror("fopen");
            exit(1);
        }
        fprintf(f, "%s,\"%s\"\n", input_field, feature_vector);
        fclose(f);
    }
}
 
 /* ================================================================= */
 /*                     flow finalisation & output                     */
 /* ================================================================= */
 static void dump_and_clear(flow_entry_t *e) {
   tw_remove(idx_of(e));
   if (WRITE_TO_CSV == 1) {
        write_to_csv(e);
   }
   if (SHOW_OUTPUT) {
     char ca[INET_ADDRSTRLEN], sa[INET_ADDRSTRLEN];
     inet_ntop(AF_INET, &e->cli_ip, ca, sizeof ca);
     inet_ntop(AF_INET, &e->srv_ip, sa, sizeof sa);
     fprintf(stderr, "Flow %s:%u ↔ %s:%u %s pkts:%d\n", ca, e->cli_port, sa,
             e->srv_port, e->is_udp ? "UDP" : "TCP", e->count);
   }
   enqueue_flow(e); /* hand to sender thread        */
   memset(e, 0, sizeof *e);
   e->tw_slot = e->tw_next = -1;
 }
 
 /* ================================================================= */
 /*                     timing-wheel advance logic                     */
 /* ================================================================= */
 static void tw_advance(time_t now_sec) {
   if (!tw_initialised) tw_init(now_sec);
 
   while (tw_now_sec < now_sec) {
     tw_now_sec++;
     tw_now_slot = (tw_now_slot + 1) & (TW_SLOTS - 1);
 
     int idx = tw_head[tw_now_slot];
     tw_head[tw_now_slot] = -1;
     while (idx != -1) {
       int nxt = table[idx].tw_next;
       table[idx].tw_slot = table[idx].tw_next = -1;
       dump_and_clear(&table[idx]);
       idx = nxt;
     }
   }
 }
 
 /* ================================================================= */
 /*                 packet tracking (called per packet)               */
 /* ================================================================= */
 static void track_packet(const struct timeval *tv, uint32_t sip, uint32_t dip,
                          uint16_t sport, uint16_t dport, uint8_t proto,
                          int tcp_syn, int tcp_fin, u_short ip_len) {
   tw_advance(tv->tv_sec);
 
   flow_key_t key = make_key(sip, dip, sport, dport, proto);
   char kbuf[64];
   snprintf(kbuf, sizeof kbuf, "%08x%04x%08x%04x%02x", key.ip1, key.port1,
            key.ip2, key.port2, key.proto);
   uint32_t h = fnv1a_32(kbuf);
 
   int found;
   int idx = find_bucket(&key, h, &found);
   if (idx < 0) {
     fprintf(stderr, "Hash-table full!\n");
     return;
   }
 
   flow_entry_t *e = &table[idx];

   if (!found && e->in_use && compare_key(&e->key, &key)) {
     tw_remove(idx);
     memset(e, 0, sizeof *e);
     e->tw_slot = e->tw_next = -1;
   }
 
   if (!found) {
     if (proto == IPPROTO_TCP && !tcp_syn) return; /* ignore mid-flow SYN-less */
     memset(e, 0, sizeof *e);
     e->in_use = 1;
     e->key = key;
     e->is_udp = (proto == IPPROTO_UDP);
     e->cli_ip = sip;
     e->srv_ip = dip;
     e->cli_port = sport;
     e->srv_port = dport;
     e->tw_slot = e->tw_next = -1;
     if (e->is_udp) tw_insert(idx, tv->tv_sec + UDP_IDLE_SEC);
   }
 
   if (compare_key(&e->key, &key)) return; /* collision miss */
 
   if (e->count < FLOW_CAP) {
     int from_cli = (sip == e->cli_ip && sport == e->cli_port);
     e->ts[e->count] = *tv;
     e->len[e->count] = (from_cli ? +1 : -1) * (int32_t)ip_len;
     e->count++;
   }
 
   if (!e->is_udp) { /* TCP FIN handling */
     if (tcp_fin) {
       if (sip == e->cli_ip && sport == e->cli_port)
         e->fin_cli_done = 1;
       else
         e->fin_srv_done = 1;
       if (e->fin_cli_done && e->fin_srv_done && e->count == FLOW_CAP)
         dump_and_clear(e);
     }
   } else { /* UDP re-schedule */
     tw_insert(idx, tv->tv_sec + UDP_IDLE_SEC);
   }
 }
 
 /* ================================================================= */
 /*                parse Ethernet/IP/TCP/UDP & call tracker           */
 /* ================================================================= */
 static int parse_and_track(const struct pcap_pkthdr *h, const u_char *pkt) {
   const struct ether_header *eth = (const struct ether_header *)pkt;
   if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;
 
   const struct ip *ip = (const struct ip *)(pkt + sizeof *eth);
   uint8_t proto = ip->ip_p;
   uint32_t sip = ip->ip_src.s_addr, dip = ip->ip_dst.s_addr;
   uint16_t sport = 0, dport = 0;
   int syn = 0, fin = 0;
   int ip_hl = ip->ip_hl * 4;
 
   if (proto == IPPROTO_TCP) {
     const struct tcphdr *th =
         (const struct tcphdr *)(pkt + sizeof *eth + ip_hl);
     sport = ntohs(th->th_sport);
     dport = ntohs(th->th_dport);
     syn = (th->th_flags & TH_SYN) != 0;
     fin = (th->th_flags & TH_FIN) != 0;
   } else if (proto == IPPROTO_UDP) {
     const struct udphdr *uh =
         (const struct udphdr *)(pkt + sizeof *eth + ip_hl);
     sport = ntohs(uh->uh_sport);
     dport = ntohs(uh->uh_dport);
   } else
     return 0;
 
   track_packet(&h->ts, sip, dip, sport, dport, proto, syn, fin,
                ntohs(ip->ip_len));
   return 1;
 }
 
 /* ================================================================= */
 /*                                main                               */
 /* ================================================================= */
 int main(int argc, char **argv) {

   if (argc == 3) {
    if (strcmp(argv[2], "coin") == 0) {
          g_evict_mode = 1;
          g_rng = (uint32_t)time(NULL);
      } else {
          fprintf(stderr, "usage: %s file.pcap [coin]\n", argv[0]);
          return 1;
      }
    } else if (argc != 2) {
      fprintf(stderr, "usage: %s file.pcap [coin]\n", argv[0]);
      return 1;
    }
 
   char err[PCAP_ERRBUF_SIZE];
   pcap_t *pc = pcap_open_offline(argv[1], err);
   if (!pc) {
     fprintf(stderr, "pcap_open: %s\n", err);
     return 1;
   }
 
   /* start sender thread */
   pthread_create(&zmq_thread, NULL, sender_thread, NULL);
 
   struct pcap_pkthdr *h;
   const u_char *pkt;
   int rc;
   while ((rc = pcap_next_ex(pc, &h, &pkt)) >= 0) {
     if (rc == 0) continue;
     parse_and_track(h, pkt);
   }
   if (rc == -1) fprintf(stderr, "pcap error: %s\n", pcap_geterr(pc));
 
   /* final flush: advance far enough to expire everything */
   struct timeval tv;
   gettimeofday(&tv, NULL);
   tw_advance(tv.tv_sec + UDP_IDLE_SEC + TW_SLOTS);
 
   for (int i = 0; i < TABLE_SIZE; ++i)
     if (table[i].in_use) dump_and_clear(&table[i]);
 
   /* shut down sender thread */
   pthread_mutex_lock(&mtx);
   exiting = 1;
   pthread_cond_signal(&cond_full);
   pthread_mutex_unlock(&mtx);
   pthread_join(zmq_thread, NULL);
 
   pcap_close(pc);
   return 0;
 }
 