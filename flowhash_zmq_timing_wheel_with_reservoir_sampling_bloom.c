/*********************************************************************
 *  flowhash_zmq_timing_wheel_reservoir_bloom.c
 *
 *  Core behavior:
 *   - Two tables: TCP and UDP (no auxiliary contender table)
 *   - UDP-only timing wheel idle flush
 *   - TCP: only start on SYN; flush at FLOW_CAP
 *   - UDP: flush on idle (timing wheel) or FLOW_CAP
 *   - JSON encode + ZMQ batch push sender thread
 *   - Optional CSV logging split by protocol
 *
 *  Contention policy (reservoir-style per bucket):
 *   - If a packet belongs to a NEW flow that collides with the incumbent in that bucket:
 *       challenger replaces incumbent with probability 1/(wins+2)
 *       (wins=0 => 1/2, wins=1 => 1/3, wins=2 => 1/4, ...)
 *     If incumbent wins: wins++ and challenger packet is dropped.
 *
 *  UDP-only Bloom filter:
 *   - Used as a UDP admission gate to suppress repeated re-admission of the same UDP flow
 *     (especially after idle expiry).
 *   - Checked ONLY when we would otherwise admit a UDP flow (empty bucket or replacement).
 *   - If "probably seen": refuse admission (drop packet).
 *   - If "definitely not seen": add to bloom and admit.
 *
 *  WARNING:
 *   - Bloom filters have false positives. A truly new UDP flow may be refused rarely.
 *   - Make UDP_BLOOM_BITS larger to reduce false positives.
 *********************************************************************/

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <jansson.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <zmq.h>

/* ---------- parameters ------------------------------------------- */
#define TABLE_SIZE (65536 * 2) /* must be power of 2 */
#define FLOW_CAP 40            /* pkts per flow      */
#define UDP_IDLE_SEC 30        /* idle timeout UDP   */
#define TW_SLOTS 256           /* must be power of 2 */
#define BUF_MAX 64             /* ring buffer slots  */
#define BATCH_SIZE 16          /* flows per JSON msg */
#define SHOW_OUTPUT 0          /* stderr debug prints */
#define WRITE_TO_CSV 1

/* ZMQ shutdown / blocking behavior */
#define ZMQ_LINGER_MS 0
#define ZMQ_SNDTIMEO_MS 100
#define ZMQ_ENDPOINT "ipc:///tmp/flowpipe"

/* ---------- UDP Bloom filter (UDP-only admission gate) ------------ */
/* Bits must be power-of-two for fast masking.                        */
/* 2^27 bits = 16MB; 2^26 bits = 8MB; 2^25 bits = 4MB                */
#define UDP_BLOOM_BITS   (1u << 27)
#define UDP_BLOOM_BYTES  (UDP_BLOOM_BITS / 8u)
#define UDP_BLOOM_K 4

static uint8_t udp_bloom[UDP_BLOOM_BYTES];

/* compile-time guards */
#if (TABLE_SIZE & (TABLE_SIZE - 1)) != 0
#error "TABLE_SIZE must be a power of two"
#endif

#if (TW_SLOTS & (TW_SLOTS - 1)) != 0
#error "TW_SLOTS must be a power of two"
#endif

#if (UDP_BLOOM_BITS & (UDP_BLOOM_BITS - 1)) != 0
#error "UDP_BLOOM_BITS must be a power of two"
#endif

/* ---------- tiny FNV-1a 32-bit ------------------------------------ */
static uint32_t fnv1a_32(const char *s) {
  uint32_t h = 0x811c9dc5u;
  while (*s) {
    h ^= (uint8_t)(*s++);
    h *= 0x01000193u;
  }
  return h;
}

/* ---------- bloom helpers ----------------------------------------- */
static inline void udp_bloom_clear(void) {
  memset(udp_bloom, 0, sizeof udp_bloom);
}

static inline void bloom_set_bit(uint32_t bit) {
  udp_bloom[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
}

static inline int bloom_get_bit(uint32_t bit) {
  return (udp_bloom[bit >> 3] >> (bit & 7u)) & 1u;
}

static inline uint32_t mix32(uint32_t x) {
  x ^= x >> 16;
  x *= 0x7feb352du;
  x ^= x >> 15;
  x *= 0x846ca68bu;
  x ^= x >> 16;
  return x;
}

/* ---------- flow key / entry ------------------------------------- */
typedef struct {
  uint32_t ip1, ip2; /* canonical src/dst order */
  uint16_t port1, port2;
  uint8_t proto; /* IPPROTO_TCP | IPPROTO_UDP */
} flow_key_t;

typedef struct flow_entry {
  int in_use;
  flow_key_t key;

  /* original orientation = first-packet perspective */
  uint32_t cli_ip, srv_ip;
  uint16_t cli_port, srv_port;

  int is_udp;

  struct timeval ts[FLOW_CAP];
  int32_t len[FLOW_CAP];  /* sign encodes direction, magnitude is ip_len */
  int count;

  /* reservoir contention: how many collisions incumbent has won */
  uint32_t wins;

  /* --- timing-wheel bookkeeping (UDP-only) --- */
  int tw_next;
  int tw_prev;
  int tw_slot;
} flow_entry_t;

static inline int idx_of(flow_entry_t *base, flow_entry_t *e) { return (int)(e - base); }

/* Returns 1 if "probably seen", 0 if "definitely not seen".
   If add_if_new=1 and definitely-not-seen, also inserts into bloom. */
static inline int udp_bloom_probably_seen_and_maybe_add(const flow_key_t *k, int add_if_new)
{
  /* hash canonical key fields directly */
  uint32_t h1 = 2166136261u;
  h1 ^= (uint32_t)k->ip1;   h1 *= 16777619u;
  h1 ^= (uint32_t)k->ip2;   h1 *= 16777619u;
  h1 ^= (uint32_t)k->port1; h1 *= 16777619u;
  h1 ^= (uint32_t)k->port2; h1 *= 16777619u;
  h1 ^= (uint32_t)k->proto; h1 *= 16777619u;

  uint32_t h2 = mix32(h1 ^ 0x9e3779b9u);
  if (h2 == 0) h2 = 0x27d4eb2du;

  uint32_t mask = (uint32_t)(UDP_BLOOM_BITS - 1u);

  for (uint32_t i = 0; i < UDP_BLOOM_K; i++) {
    uint32_t bit = (h1 + i * h2) & mask;
    if (!bloom_get_bit(bit)) {
      if (add_if_new) {
        for (uint32_t j = 0; j < UDP_BLOOM_K; j++) {
          uint32_t b2 = (h1 + j * h2) & mask;
          bloom_set_bit(b2);
        }
      }
      return 0; /* definitely not seen */
    }
  }
  return 1; /* probably seen */
}

/* ================================================================= */
/*                     Tables: split by protocol                       */
/* ================================================================= */
static flow_entry_t table_tcp[TABLE_SIZE] = {0};
static flow_entry_t table_udp[TABLE_SIZE] = {0};

/* ================================================================= */
/*                           Timing-wheel (UDP-only)                  */
/* ================================================================= */
static int tw_head_udp[TW_SLOTS];

static time_t tw_now_sec = 0;
static int tw_now_slot = 0;
static int tw_initialised = 0;
static time_t last_pcap_sec = 0;

static volatile sig_atomic_t g_sigquit_dump_full = 0;
static volatile sig_atomic_t g_in_tw = 0;
static volatile sig_atomic_t g_tw_now_arg = 0;

/* ---------- stats ------------------------------------------------- */
static uint64_t st_flows_inserted = 0;
static uint64_t st_flows_matched  = 0;
static uint64_t st_packets_tracked = 0;

static uint64_t st_collisions = 0;
static uint64_t st_battles = 0;
static uint64_t st_challenger_wins = 0;
static uint64_t st_incumbent_wins  = 0;

static uint64_t st_udp_bloom_refused = 0;

/* ---------- ZMQ batching ring buffer ------------------------------ */
typedef struct {
  flow_entry_t slot;
} buf_item_t;

static buf_item_t flow_buf[BUF_MAX];
static size_t head = 0, tail = 0, fill = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_full = PTHREAD_COND_INITIALIZER;
static pthread_t zmq_thread;
static int exiting = 0;

/* ================================================================= */
/*                           Timing-wheel helpers                     */
/* ================================================================= */
static void tw_init(time_t start_sec) {
  for (int i = 0; i < TW_SLOTS; ++i) {
    tw_head_udp[i] = -1;
  }
  tw_now_sec = start_sec;
  tw_now_slot = (int)(start_sec % TW_SLOTS);
  tw_initialised = 1;
}

static void tw_remove_generic(flow_entry_t *base, int *tw_head, int idx)
{
  flow_entry_t *e = &base[idx];
  if (e->tw_slot < 0) return;

  int slot = e->tw_slot;

  if (e->tw_prev != -1)
    base[e->tw_prev].tw_next = e->tw_next;
  else
    tw_head[slot] = e->tw_next;

  if (e->tw_next != -1)
    base[e->tw_next].tw_prev = e->tw_prev;

  e->tw_slot = -1;
  e->tw_next = -1;
  e->tw_prev = -1;
}

static void tw_insert_generic(flow_entry_t *base, int *tw_head, int idx, time_t exp_sec)
{
  flow_entry_t *e = &base[idx];

  if (e->tw_slot >= 0)
    tw_remove_generic(base, tw_head, idx);

  int slot = (int)(exp_sec % TW_SLOTS);

  e->tw_slot = slot;
  e->tw_prev = -1;
  e->tw_next = tw_head[slot];

  if (tw_head[slot] != -1)
    base[tw_head[slot]].tw_prev = idx;

  tw_head[slot] = idx;
}

/* ================================================================= */
/*                       JSON encoding helpers                        */
/* ================================================================= */
static json_t *json_from_entry(const flow_entry_t *f) {
  if (f->count <= 0) return json_object();

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
  json_object_set_new(root, "wins", json_integer((json_int_t)f->wins));

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
  }
  flow_buf[head].slot = *src;
  head = (head + 1) % BUF_MAX;
  fill++;

  pthread_cond_signal(&cond_full);
  pthread_mutex_unlock(&mtx);
}

static void *sender_thread(void *arg) {
  (void)arg;

  void *ctx = zmq_ctx_new();
  void *sock = zmq_socket(ctx, ZMQ_PUSH);

  int linger = ZMQ_LINGER_MS;
  zmq_setsockopt(sock, ZMQ_LINGER, &linger, sizeof(linger));

  int sndtimeo = ZMQ_SNDTIMEO_MS;
  zmq_setsockopt(sock, ZMQ_SNDTIMEO, &sndtimeo, sizeof(sndtimeo));

  if (zmq_bind(sock, ZMQ_ENDPOINT) != 0) {
    fprintf(stderr, "zmq_bind(%s) failed: %s\n", ZMQ_ENDPOINT, zmq_strerror(errno));
    zmq_close(sock);
    zmq_ctx_term(ctx);
    return NULL;
  }

  for (;;) {
    pthread_mutex_lock(&mtx);
    while (fill == 0 && !exiting) {
      pthread_cond_wait(&cond_full, &mtx);
    }

    if (exiting && fill == 0) {
      pthread_mutex_unlock(&mtx);
      break;
    }

    json_t *batch = json_array();
    int sent = 0;

    while (fill > 0 && sent < BATCH_SIZE) {
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
      (void)zmq_send(sock, txt, strlen(txt), ZMQ_DONTWAIT);
      free(txt);
    }
    json_decref(batch);
  }

  zmq_close(sock);
  zmq_ctx_term(ctx);
  return NULL;
}

/* ================================================================= */
/*                         helper functions                           */
/* ================================================================= */
static int compare_key(const flow_key_t *a, const flow_key_t *b) {
  return !(a->ip1 == b->ip1 && a->ip2 == b->ip2 &&
           a->port1 == b->port1 && a->port2 == b->port2 &&
           a->proto == b->proto);
}

static flow_key_t make_key(uint32_t s_ip, uint32_t d_ip, uint16_t s_pt,
                           uint16_t d_pt, uint8_t proto) {
  flow_key_t k;
  if (ntohl(s_ip) < ntohl(d_ip)) {
    k.ip1 = s_ip; k.ip2 = d_ip;
    k.port1 = s_pt; k.port2 = d_pt;
  } else if (ntohl(s_ip) > ntohl(d_ip)) {
    k.ip1 = d_ip; k.ip2 = s_ip;
    k.port1 = d_pt; k.port2 = s_pt;
  } else {
    k.ip1 = s_ip; k.ip2 = d_ip;
    if (s_pt > d_pt) { uint16_t t = s_pt; s_pt = d_pt; d_pt = t; }
    k.port1 = s_pt; k.port2 = d_pt;
  }
  k.proto = proto;
  return k;
}

/* challenger replaces incumbent with probability 1/(wins+2) */
static inline int challenger_wins(uint32_t incumbent_wins) {
  uint32_t denom = incumbent_wins + 2u;
  return ((uint32_t)rand() % denom) == 0u;
}

/* ================================================================= */
/*                         CSV logging                                */
/* ================================================================= */
static void write_to_csv(flow_entry_t *e) {
  if (e->count != FLOW_CAP) return;

  char ip_small[INET_ADDRSTRLEN], ip_large[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &e->key.ip1, ip_small, sizeof(ip_small));
  inet_ntop(AF_INET, &e->key.ip2, ip_large, sizeof(ip_large));

  char input_field[256];
  snprintf(input_field, sizeof(input_field), "%s%d%s%d%s",
           ip_small, e->key.port1,
           ip_large, e->key.port2,
           e->is_udp ? "UDP" : "TCP");

  char feature_vector[4096];
  size_t w = 0;
  w += (size_t)snprintf(feature_vector + w, sizeof(feature_vector) - w, "[");

  double ts_0 = e->ts[0].tv_sec + e->ts[0].tv_usec / 1e6;
  for (int i = 0; i < e->count; ++i) {
    double ts = e->ts[i].tv_sec + e->ts[i].tv_usec / 1e6;
    double offset = ts - ts_0;
    if (e->len[i] < 0) offset *= -1;

    w += (size_t)snprintf(feature_vector + w, sizeof(feature_vector) - w,
                          "(%.6f, %.1f)%s",
                          offset, (double)e->len[i],
                          (i < e->count - 1) ? ", " : "");
    if (w >= sizeof(feature_vector)) break;
  }

  if (w < sizeof(feature_vector))
    (void)snprintf(feature_vector + w, sizeof(feature_vector) - w, "]");

  const char *fname = e->is_udp
    ? "flow_output_timing_wheel_reservoir_udp.csv"
    : "flow_output_timing_wheel_reservoir_tcp.csv";

  FILE *f = fopen(fname, "a");
  if (!f) { perror("fopen"); exit(1); }
  fprintf(f, "%s,\"%s\"\n", input_field, feature_vector);
  fclose(f);
}

/* ================================================================= */
/*                     flow finalisation & output                     */
/* ================================================================= */
static void dump_and_clear(flow_entry_t *base, flow_entry_t *e, int *tw_head) {
  if (e->is_udp && base == table_udp) {
    int idx = idx_of(base, e);
    tw_remove_generic(base, tw_head, idx);
  }

  if (WRITE_TO_CSV) write_to_csv(e);

  if (SHOW_OUTPUT) {
    char ca[INET_ADDRSTRLEN], sa[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->cli_ip, ca, sizeof ca);
    inet_ntop(AF_INET, &e->srv_ip, sa, sizeof sa);
    fprintf(stderr, "Flow %s:%u ↔ %s:%u %s pkts:%d wins=%u\n",
            ca, e->cli_port, sa, e->srv_port, e->is_udp ? "UDP" : "TCP",
            e->count, e->wins);
  }

  enqueue_flow(e);

  memset(e, 0, sizeof *e);
  e->tw_slot = e->tw_next = e->tw_prev = -1;
}

/* ================================================================= */
/*                 timing-wheel advance logic (UDP-only expiry)        */
/* ================================================================= */
static void expire_slot_list_udp(int slot) {
  int idx = tw_head_udp[slot];
  tw_head_udp[slot] = -1;

  while (idx != -1) {
    int nxt = table_udp[idx].tw_next;
    table_udp[idx].tw_slot = table_udp[idx].tw_next = -1;
    dump_and_clear(table_udp, &table_udp[idx], tw_head_udp);
    idx = nxt;
  }
}

static void tw_advance(time_t now_sec) {
  g_in_tw = 1;
  g_tw_now_arg = (sig_atomic_t)now_sec;

  if (!tw_initialised) tw_init(now_sec);

  if (now_sec <= tw_now_sec) {
    g_in_tw = 0;
    return;
  }

  time_t delta = now_sec - tw_now_sec;

  /* BIG JUMP: expire everything UDP */
  if (delta >= TW_SLOTS) {
    for (int s = 0; s < TW_SLOTS; ++s) expire_slot_list_udp(s);
    tw_now_sec  = now_sec;
    tw_now_slot = (int)(now_sec % TW_SLOTS);
    g_in_tw = 0;
    return;
  }

  /* step */
  while (tw_now_sec < now_sec) {
    tw_now_sec++;
    tw_now_slot = (tw_now_slot + 1) & (TW_SLOTS - 1);
    expire_slot_list_udp(tw_now_slot);
  }

  g_in_tw = 0;
}

/* ================================================================= */
/*                 packet tracking (called per packet)               */
/* ================================================================= */
static void init_new_entry(flow_entry_t *e, flow_key_t key,
                           uint32_t sip, uint32_t dip,
                           uint16_t sport, uint16_t dport,
                           uint8_t proto)
{
  memset(e, 0, sizeof *e);
  e->in_use = 1;
  e->key = key;
  e->is_udp = (proto == IPPROTO_UDP);

  e->cli_ip = sip;
  e->srv_ip = dip;
  e->cli_port = sport;
  e->srv_port = dport;

  e->wins = 0;
  e->tw_slot = e->tw_next = e->tw_prev = -1;
}

/* Decide if we can admit a UDP flow (Bloom gate). Returns 1 if allowed, 0 if refused. */
static inline int udp_admission_allowed(const flow_key_t *key) {
  int seen = udp_bloom_probably_seen_and_maybe_add(key, /*add_if_new=*/1);
  if (seen) {
    st_udp_bloom_refused++;
    return 0;
  }
  return 1;
}

static void track_packet(const struct timeval *tv, uint32_t sip, uint32_t dip,
                         uint16_t sport, uint16_t dport, uint8_t proto,
                         int tcp_syn, uint16_t ip_len)
{
  /* Keep UDP expiry correct */
  tw_advance(tv->tv_sec);

  flow_key_t key = make_key(sip, dip, sport, dport, proto);

  char kbuf[64];
  snprintf(kbuf, sizeof kbuf, "%08x%04x%08x%04x%02x",
           key.ip1, key.port1, key.ip2, key.port2, key.proto);
  uint32_t h = fnv1a_32(kbuf);
  uint32_t p = h & (TABLE_SIZE - 1);

  flow_entry_t *base = (proto == IPPROTO_UDP) ? table_udp : table_tcp;
  int *tw_head = (proto == IPPROTO_UDP) ? tw_head_udp : NULL;

  flow_entry_t *m = &base[p];

  /* If empty bucket: admit directly (UDP subject to bloom) */
  if (!m->in_use) {
    if (proto == IPPROTO_TCP && !tcp_syn) return;

    if (proto == IPPROTO_UDP) {
      if (!udp_admission_allowed(&key)) return;
    }

    init_new_entry(m, key, sip, dip, sport, dport, proto);
    st_flows_inserted++;
  } else if (!compare_key(&m->key, &key)) {
    /* match */
    st_flows_matched++;
  } else {
    /* collision with incumbent */
    st_collisions++;
    st_battles++;

    if (proto == IPPROTO_TCP && !tcp_syn) return;

    /* Reservoir-style replacement */
    if (challenger_wins(m->wins)) {
      /* Challenger would replace incumbent: apply UDP bloom gate first */
      if (proto == IPPROTO_UDP) {
        if (!udp_admission_allowed(&key)) {
          /* if refused, treat as challenger dropped; incumbent remains */
          return;
        }
      }

      st_challenger_wins++;

      /* remove incumbent from wheel if UDP */
      if (proto == IPPROTO_UDP && tw_head != NULL) {
        int idx = (int)p;
        tw_remove_generic(base, tw_head, idx);
      }

      init_new_entry(m, key, sip, dip, sport, dport, proto);
      st_flows_inserted++;
    } else {
      /* incumbent stays */
      st_incumbent_wins++;
      m->wins++;
      return; /* drop challenger packet */
    }
  }

  /* Track packet into selected entry */
  if (m->count < FLOW_CAP) {
    int from_cli = (sip == m->cli_ip && sport == m->cli_port);
    m->ts[m->count] = *tv;
    m->len[m->count] = (from_cli ? +1 : -1) * (int32_t)ip_len;
    m->count++;
    st_packets_tracked++;
  }

  /* UDP: reschedule idle expiry */
  if (proto == IPPROTO_UDP && tw_head != NULL) {
    tw_insert_generic(base, tw_head, (int)p, tv->tv_sec + UDP_IDLE_SEC);
  }

  /* Flush on FLOW_CAP */
  if (m->count == FLOW_CAP) {
    dump_and_clear(base, m, tw_head);
  }
}

/* ================================================================= */
/*                parse Ethernet/IP/TCP/UDP & call tracker            */
/* ================================================================= */
static int parse_and_track(const struct pcap_pkthdr *h, const u_char *pkt) {
  const struct ether_header *eth = (const struct ether_header *)pkt;
  if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;

  const struct ip *ip = (const struct ip *)(pkt + sizeof *eth);
  uint8_t proto = ip->ip_p;
  uint32_t sip = ip->ip_src.s_addr, dip = ip->ip_dst.s_addr;

  uint16_t sport = 0, dport = 0;
  int syn = 0;

  int ip_hl = ip->ip_hl * 4;

  if (proto == IPPROTO_TCP) {
    const struct tcphdr *th = (const struct tcphdr *)(pkt + sizeof *eth + ip_hl);
    sport = ntohs(th->th_sport);
    dport = ntohs(th->th_dport);
    syn = (th->th_flags & TH_SYN) != 0;
  } else if (proto == IPPROTO_UDP) {
    const struct udphdr *uh = (const struct udphdr *)(pkt + sizeof *eth + ip_hl);
    sport = ntohs(uh->uh_sport);
    dport = ntohs(uh->uh_dport);
  } else {
    return 0;
  }

  last_pcap_sec = h->ts.tv_sec;
  track_packet(&h->ts, sip, dip, sport, dport, proto, syn, ntohs(ip->ip_len));
  return 1;
}

static void on_sigquit(int sig) {
  (void)sig;
  g_sigquit_dump_full = 1;

  char buf[256];
  int n = snprintf(buf, sizeof(buf),
    "\n=== SIGQUIT RECEIVED ===\n"
    "in_tw=%d tw_arg=%d tw_now_sec=%ld slot=%d\n"
    "ZMQ fill=%zu exiting=%d\n",
    (int)g_in_tw, (int)g_tw_now_arg, (long)tw_now_sec, tw_now_slot,
    fill, exiting);
  if (n > 0) (void)write(STDERR_FILENO, buf, (size_t)n);
}

/* ================================================================= */
/*                                main                               */
/* ================================================================= */
int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s file.pcap\n", argv[0]);
    return 1;
  }
  signal(SIGQUIT, on_sigquit);  /* Ctrl+\ */

  srand((unsigned)time(NULL));

  /* init bloom + wheel */
  udp_bloom_clear();
  for (int i = 0; i < TW_SLOTS; ++i) tw_head_udp[i] = -1;

  char err[PCAP_ERRBUF_SIZE];
  fprintf(stderr, "main: starting\n");
  pcap_t *pc = pcap_open_offline(argv[1], err);
  if (!pc) {
    fprintf(stderr, "pcap_open: %s\n", err);
    return 1;
  }
  fprintf(stderr, "main: pcap opened\n");

  if (pthread_create(&zmq_thread, NULL, sender_thread, NULL) != 0) {
    perror("pthread_create");
    pcap_close(pc);
    return 1;
  }
  fprintf(stderr, "main: sender thread created\n");

  struct pcap_pkthdr *h;
  const u_char *pkt;
  int rc;
  uint64_t iters = 0, pkts = 0, zeros = 0;

  while ((rc = pcap_next_ex(pc, &h, &pkt)) >= 0) {
    iters++;

    if (rc == 0) {
      zeros++;
      if ((zeros % 100000ULL) == 0) {
        fprintf(stderr, "pcap_next_ex: rc==0 zeros=%" PRIu64 " iters=%" PRIu64 "\n",
                zeros, iters);
      }
      continue;
    }

    pkts++;
    if ((pkts % 10000ULL) == 0) {
      fprintf(stderr, "pcap: pkts=%" PRIu64 " iters=%" PRIu64 " last_ts=%ld\n",
              pkts, iters, (long)h->ts.tv_sec);
    }

    parse_and_track(h, pkt);
  }

  if (rc == -1) fprintf(stderr, "pcap error: %s\n", pcap_geterr(pc));
  fprintf(stderr, "main: pcap loop done rc=%d\n", rc);

  /* final flush: advance far enough to expire all UDP flows */
  if (last_pcap_sec != 0) {
    tw_advance(last_pcap_sec + UDP_IDLE_SEC + TW_SLOTS);
  }

  /* flush both tables */
  for (int i = 0; i < TABLE_SIZE; ++i) {
    if (table_tcp[i].in_use) dump_and_clear(table_tcp, &table_tcp[i], NULL);
    if (table_udp[i].in_use) dump_and_clear(table_udp, &table_udp[i], tw_head_udp);
  }

  pthread_mutex_lock(&mtx);
  exiting = 1;
  pthread_cond_broadcast(&cond_full);
  pthread_mutex_unlock(&mtx);

  fprintf(stderr, "main: setting exiting=1 and joining sender (fill=%zu)\n", fill);
  pthread_join(zmq_thread, NULL);

  pcap_close(pc);

  fprintf(stderr,
          "stats: inserted=%" PRIu64 " matched=%" PRIu64
          " pkts_tracked=%" PRIu64
          " collisions=%" PRIu64 " battles=%" PRIu64
          " challenger_wins=%" PRIu64 " incumbent_wins=%" PRIu64
          " udp_bloom_refused=%" PRIu64 "\n",
          st_flows_inserted, st_flows_matched,
          st_packets_tracked,
          st_collisions, st_battles,
          st_challenger_wins, st_incumbent_wins,
          st_udp_bloom_refused);

  return 0;
}
