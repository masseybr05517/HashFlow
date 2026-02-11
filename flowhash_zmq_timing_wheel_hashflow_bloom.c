/*********************************************************************
 *  flowhash_zmq_timing_wheel_hashflow_bloom.c
 *
 *  HashFlow-style contention policy (close to provided pseudocode):
 *   - Main table T has 2 hash positions: h1(id), h2(id)
 *   - Auxiliary table A has 1 position: g(id)
 *   - TCP: only start on SYN (drop non-SYN packets that don't match existing)
 *   - Export/flush on FLOW_CAP or TCP FIN flag
 *   - UDP: idle expiry via timing wheel (for BOTH T_udp and A_udp)
 *   - UDP Bloom gate: applied only when admitting a *new* UDP flow (into T or A)
 *
 *  Keeps your original setup:
 *   - Split by protocol
 *   - ZMQ batch sender thread
 *   - Optional CSV logging split by protocol
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
#define TABLE_SIZE (4096)      /* must be power of 2 */
#define AUX_SIZE   (4096)      /* must be power of 2; keep same as main by default */
#define FLOW_CAP 40            /* m = 40 in pseudocode */
#define UDP_IDLE_SEC 30        /* idle timeout UDP */
#define TW_SLOTS 256           /* must be power of 2 */
#define BUF_MAX 64             /* ring buffer slots */
#define BATCH_SIZE 16          /* flows per JSON msg */
#define SHOW_OUTPUT 0
#define WRITE_TO_CSV 1

/* ZMQ shutdown / blocking behavior */
#define ZMQ_LINGER_MS 0
#define ZMQ_SNDTIMEO_MS 100
#define ZMQ_ENDPOINT "ipc:///tmp/flowpipe"

/* ---------- UDP Bloom filter (UDP-only admission gate) ------------ */
#define UDP_BLOOM_BITS   (1u << 28)
#define UDP_BLOOM_BYTES  (UDP_BLOOM_BITS / 8u)
#define UDP_BLOOM_K 4

static uint8_t udp_bloom[UDP_BLOOM_BYTES];

/* compile-time guards */
#if (TABLE_SIZE & (TABLE_SIZE - 1)) != 0
#error "TABLE_SIZE must be a power of two"
#endif
#if (AUX_SIZE & (AUX_SIZE - 1)) != 0
#error "AUX_SIZE must be a power of two"
#endif
#if (TW_SLOTS & (TW_SLOTS - 1)) != 0
#error "TW_SLOTS must be a power of two"
#endif
#if (UDP_BLOOM_BITS & (UDP_BLOOM_BITS - 1)) != 0
#error "UDP_BLOOM_BITS must be a power of two"
#endif

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

  /* --- timing-wheel bookkeeping (UDP-only) --- */
  int tw_next;
  int tw_prev;
  int tw_slot;
} flow_entry_t;

/* ================================================================= */
/*                       Tiny hash helpers                             */
/* ================================================================= */
static inline uint32_t mix32(uint32_t x) {
  x ^= x >> 16;
  x *= 0x7feb352du;
  x ^= x >> 15;
  x *= 0x846ca68bu;
  x ^= x >> 16;
  return x;
}

static inline uint32_t hash_key32(const flow_key_t *k, uint32_t seed) {
  uint32_t h = 2166136261u ^ seed;
  h ^= (uint32_t)k->ip1;   h *= 16777619u;
  h ^= (uint32_t)k->ip2;   h *= 16777619u;
  h ^= (uint32_t)k->port1; h *= 16777619u;
  h ^= (uint32_t)k->port2; h *= 16777619u;
  h ^= (uint32_t)k->proto; h *= 16777619u;
  return mix32(h);
}

/* h1/h2/g indices */
static inline uint32_t h1_idx(const flow_key_t *k) { return hash_key32(k, 0xA1B2C3D4u) & (TABLE_SIZE - 1u); }
static inline uint32_t h2_idx(const flow_key_t *k) { return hash_key32(k, 0x1B2C3D4Au) & (TABLE_SIZE - 1u); }
static inline uint32_t g_idx (const flow_key_t *k) { return hash_key32(k, 0xC0FFEE11u) & (AUX_SIZE   - 1u); }

/* ================================================================= */
/*                         Bloom helpers                               */
/* ================================================================= */
static inline void udp_bloom_clear(void) { memset(udp_bloom, 0, sizeof udp_bloom); }

static inline void bloom_set_bit(uint32_t bit) { udp_bloom[bit >> 3] |= (uint8_t)(1u << (bit & 7u)); }
static inline int  bloom_get_bit(uint32_t bit) { return (udp_bloom[bit >> 3] >> (bit & 7u)) & 1u; }

/* Returns 1 if "probably seen", 0 if "definitely not seen".
   If add_if_new=1 and definitely-not-seen, also inserts into bloom. */
static inline int udp_bloom_probably_seen_and_maybe_add(const flow_key_t *k, int add_if_new) {
  uint32_t h1 = hash_key32(k, 0x13579BDFu);
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
      return 0;
    }
  }
  return 1;
}

/* Decide if we can admit a UDP flow (Bloom gate). Returns 1 if allowed, 0 if refused. */
static inline int udp_admission_allowed(const flow_key_t *key, uint64_t *st_udp_bloom_refused) {
  int seen = udp_bloom_probably_seen_and_maybe_add(key, /*add_if_new=*/1);
  if (seen) {
    (*st_udp_bloom_refused)++;
    return 0;
  }
  return 1;
}

/* ================================================================= */
/*                     Tables: split by protocol                       */
/* ================================================================= */
/* Main tables T */
static flow_entry_t T_tcp[TABLE_SIZE] = {0};
static flow_entry_t T_udp[TABLE_SIZE] = {0};
/* Aux tables A */
static flow_entry_t A_tcp[AUX_SIZE] = {0};
static flow_entry_t A_udp[AUX_SIZE] = {0};

/* ================================================================= */
/*                           Timing-wheel (UDP-only)                   */
/* ================================================================= */
static int tw_head_T_udp[TW_SLOTS];
static int tw_head_A_udp[TW_SLOTS];

static time_t tw_now_sec = 0;
static int tw_now_slot = 0;
static int tw_initialised = 0;
static time_t last_pcap_sec = 0;

static volatile sig_atomic_t g_in_tw = 0;

/* ---------- stats ------------------------------------------------- */
static uint64_t st_inserted_T = 0;
static uint64_t st_inserted_A = 0;
static uint64_t st_matched = 0;
static uint64_t st_packets_tracked = 0;
static uint64_t st_promoted_A_to_T = 0;
static uint64_t st_evicted_T_to_A = 0;
static uint64_t st_udp_bloom_refused = 0;

/* ---------- ZMQ batching ring buffer ------------------------------ */
typedef struct { flow_entry_t slot; } buf_item_t;

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
    tw_head_T_udp[i] = -1;
    tw_head_A_udp[i] = -1;
  }
  tw_now_sec = start_sec;
  tw_now_slot = (int)(start_sec % TW_SLOTS);
  tw_initialised = 1;
}

static void tw_remove_generic(flow_entry_t *base, int *tw_head, int idx) {
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

static void tw_insert_generic(flow_entry_t *base, int *tw_head, int idx, time_t exp_sec) {
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
static inline int key_eq(const flow_key_t *a, const flow_key_t *b) {
  return (a->ip1 == b->ip1 && a->ip2 == b->ip2 &&
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

  e->tw_slot = e->tw_next = e->tw_prev = -1;
}

/* ================================================================= */
/*                         CSV logging                                */
/* ================================================================= */
static void write_to_csv(const flow_entry_t *e, const char *fname) {
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

  FILE *f = fopen(fname, "a");
  if (!f) { perror("fopen"); exit(1); }
  fprintf(f, "%s,\"%s\"\n", input_field, feature_vector);
  fclose(f);
}

/* ================================================================= */
/*                     flow finalisation & output                     */
/* ================================================================= */
static void dump_and_clear_udp(flow_entry_t *base, int *tw_head, int idx, const char *csv_name) {
  flow_entry_t *e = &base[idx];
  if (e->in_use) {
    if (tw_head) tw_remove_generic(base, tw_head, idx);

    if (WRITE_TO_CSV) write_to_csv(e, csv_name);

    if (SHOW_OUTPUT) {
      char ca[INET_ADDRSTRLEN], sa[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &e->cli_ip, ca, sizeof ca);
      inet_ntop(AF_INET, &e->srv_ip, sa, sizeof sa);
      fprintf(stderr, "Flow %s:%u ↔ %s:%u %s pkts:%d\n",
              ca, e->cli_port, sa, e->srv_port, e->is_udp ? "UDP" : "TCP",
              e->count);
    }

    enqueue_flow(e);
  }

  memset(e, 0, sizeof *e);
  e->tw_slot = e->tw_next = e->tw_prev = -1;
}

static void dump_and_clear_tcp(flow_entry_t *base, int idx, const char *csv_name) {
  flow_entry_t *e = &base[idx];
  if (e->in_use) {
    if (WRITE_TO_CSV) write_to_csv(e, csv_name);
    enqueue_flow(e);
  }
  memset(e, 0, sizeof *e);
  e->tw_slot = e->tw_next = e->tw_prev = -1;
}

/* ================================================================= */
/*                 timing-wheel advance logic (UDP-only expiry)        */
/* ================================================================= */
static void expire_slot_list_udp(flow_entry_t *base, int *tw_head, int slot, const char *csv_name) {
  int idx = tw_head[slot];
  tw_head[slot] = -1;

  while (idx != -1) {
    int nxt = base[idx].tw_next;
    base[idx].tw_slot = base[idx].tw_next = -1;
    dump_and_clear_udp(base, tw_head, idx, csv_name);
    idx = nxt;
  }
}

static void tw_advance(time_t now_sec) {
  g_in_tw = 1;

  if (!tw_initialised) tw_init(now_sec);

  if (now_sec <= tw_now_sec) {
    g_in_tw = 0;
    return;
  }

  time_t delta = now_sec - tw_now_sec;

  /* BIG JUMP: expire everything UDP */
  if (delta >= TW_SLOTS) {
    for (int s = 0; s < TW_SLOTS; ++s) {
      expire_slot_list_udp(T_udp, tw_head_T_udp, s, "flow_output_hashflow_udp.csv");
      expire_slot_list_udp(A_udp, tw_head_A_udp, s, "flow_output_hashflow_udp.csv");
    }
    tw_now_sec  = now_sec;
    tw_now_slot = (int)(now_sec % TW_SLOTS);
    g_in_tw = 0;
    return;
  }

  while (tw_now_sec < now_sec) {
    tw_now_sec++;
    tw_now_slot = (tw_now_slot + 1) & (TW_SLOTS - 1);
    expire_slot_list_udp(T_udp, tw_head_T_udp, tw_now_slot, "flow_output_hashflow_udp.csv");
    expire_slot_list_udp(A_udp, tw_head_A_udp, tw_now_slot, "flow_output_hashflow_udp.csv");
  }

  g_in_tw = 0;
}

/* ================================================================= */
/*                 Packet tracking helper: append pkt                  */
/* ================================================================= */
static inline void append_packet(flow_entry_t *e, const struct timeval *tv,
                                 uint32_t sip, uint16_t sport, uint16_t ip_len) {
  if (e->count >= FLOW_CAP) return;
  int from_cli = (sip == e->cli_ip && sport == e->cli_port);
  e->ts[e->count] = *tv;
  e->len[e->count] = (from_cli ? +1 : -1) * (int32_t)ip_len;
  e->count++;
  st_packets_tracked++;
}

/* ================================================================= */
/*               HashFlow-style move/evict helpers                     */
/* ================================================================= */

/* Try to relocate an evicted main-table entry to its alternate bucket if empty;
   otherwise push it into its auxiliary slot (overwriting). */
static inline void relocate_or_aux(
    flow_entry_t *T, uint32_t Tmask,
    flow_entry_t *A, uint32_t Amask,
    flow_entry_t evicted,
    int is_udp,
    int *tw_head_T, int *tw_head_A,
    time_t now_sec)
{
  if (!evicted.in_use) return;

  uint32_t p1 = hash_key32(&evicted.key, 0xA1B2C3D4u) & Tmask;
  uint32_t p2 = hash_key32(&evicted.key, 0x1B2C3D4Au) & Tmask;

  /* figure which slot it's NOT currently in; choose alternate if empty */
  uint32_t alt = p1;
  if (T[p1].in_use && key_eq(&T[p1].key, &evicted.key)) alt = p2;
  else if (T[p2].in_use && key_eq(&T[p2].key, &evicted.key)) alt = p1;
  else {
    /* if we don't know, just prefer p1 then p2 */
    alt = (!T[p1].in_use) ? p1 : p2;
  }

  if (!T[alt].in_use) {
    T[alt] = evicted;
    if (is_udp) tw_insert_generic(T, tw_head_T, (int)alt, now_sec + UDP_IDLE_SEC);
    return;
  }

  /* push to auxiliary (overwrite), remove old A wheel if needed */
  uint32_t ga = hash_key32(&evicted.key, 0xC0FFEE11u) & Amask;
  if (is_udp && A[ga].in_use) tw_remove_generic(A, tw_head_A, (int)ga);
  A[ga] = evicted;
  if (is_udp) tw_insert_generic(A, tw_head_A, (int)ga, now_sec + UDP_IDLE_SEC);
  st_evicted_T_to_A++;
}

/* ================================================================= */
/*                 HashFlow-style per-packet logic                     */
/* ================================================================= */
static void track_packet(const struct timeval *tv,
                         uint32_t sip, uint32_t dip,
                         uint16_t sport, uint16_t dport,
                         uint8_t proto,
                         int tcp_syn,
                         int tcp_fin,
                         uint16_t ip_len)
{
  /* Keep UDP expiry correct */
  tw_advance(tv->tv_sec);

  flow_key_t key = make_key(sip, dip, sport, dport, proto);

  int is_udp = (proto == IPPROTO_UDP);

  flow_entry_t *T = is_udp ? T_udp : T_tcp;
  flow_entry_t *A = is_udp ? A_udp : A_tcp;

  int *tw_head_T = is_udp ? tw_head_T_udp : NULL;
  int *tw_head_A = is_udp ? tw_head_A_udp : NULL;

  const uint32_t Tmask = (TABLE_SIZE - 1u);
  const uint32_t Amask = (AUX_SIZE   - 1u);

  uint32_t p1 = h1_idx(&key);
  uint32_t p2 = h2_idx(&key);
  uint32_t ga = g_idx(&key);

  flow_entry_t *e = NULL;

  /* ---------- SYN path (TCP only) -------------------------------- */
  if (!is_udp && tcp_syn) {
    /* h1 empty -> insert */
    if (!T[p1].in_use) {
      init_new_entry(&T[p1], key, sip, dip, sport, dport, proto);
      st_inserted_T++;
      e = &T[p1];
    }
    /* h1 collision -> try h2 empty -> insert */
    else if (!key_eq(&T[p1].key, &key) && !T[p2].in_use) {
      init_new_entry(&T[p2], key, sip, dip, sport, dport, proto);
      st_inserted_T++;
      e = &T[p2];
    }
    /* else collision in both -> write into A[g] (overwrite), then maybe promote */
    else if (!key_eq(&T[p1].key, &key) && !key_eq(&T[p2].key, &key)) {
      /* overwrite A[g] */
      if (A[ga].in_use) {
        /* TCP: no wheel */
      }
      init_new_entry(&A[ga], key, sip, dip, sport, dport, proto);
      st_inserted_A++;

      /* "if A[idx] != empty then move the flow to table T if it is large" */
      /* choose pos among h1/h2 of A[ga].id with min pcks */
      uint32_t q1 = h1_idx(&A[ga].key);
      uint32_t q2 = h2_idx(&A[ga].key);
      uint32_t pos = q1;
      int min = T[q1].in_use ? T[q1].count : 0;
      int v2  = T[q2].in_use ? T[q2].count : 0;
      if (v2 < min) { pos = q2; min = v2; }

      if (A[ga].count > min) {
        /* promote A->T[pos], and place "new syn flow" into A[g] per pseudocode */
        flow_entry_t promoted = A[ga];
        flow_entry_t evicted  = T[pos];

        T[pos] = promoted;
        A[ga] = evicted; /* per pseudocode: A[idx] = [p.id,1,...] — we approximate by putting evicted back */
        /* (For SYN-case in pseudocode, they set A[idx] = new flow; since we already created it in A[ga],
            and then promoted it, we keep something in A[ga] rather than empty. This keeps memory utilization similar.) */
        st_promoted_A_to_T++;

        /* No relocation step described in SYN block beyond this; keep it simple and stable. */
      }

      e = &A[ga]; /* track into aux entry for this packet */
    }
    else {
      /* it matched either T[p1] or T[p2] */
      if (key_eq(&T[p1].key, &key)) e = &T[p1];
      else if (key_eq(&T[p2].key, &key)) e = &T[p2];
    }

    if (e) {
      append_packet(e, tv, sip, sport, ip_len);
      if (e->count == FLOW_CAP || (tcp_fin && !e->is_udp)) {
        dump_and_clear_tcp(T, (int)(e - T), "flow_output_hashflow_tcp.csv");
      }
    }
    return;
  }

  /* ---------- Non-SYN path (and UDP always uses this path) -------- */
  /* TCP: if not SYN and doesn't match, we drop (like your rule). */
  /* Step 1: check T[h1], T[h2] match */
  if (T[p1].in_use && key_eq(&T[p1].key, &key)) {
    e = &T[p1];
    st_matched++;
  } else if (T[p2].in_use && key_eq(&T[p2].key, &key)) {
    e = &T[p2];
    st_matched++;
  } else if (A[ga].in_use && key_eq(&A[ga].key, &key)) {
    e = &A[ga];
    st_matched++;
  } else {
    /* new flow attempt (UDP) or unmatched TCP non-SYN */
    if (!is_udp && !tcp_syn) return; /* TCP start-on-SYN rule */

    /* UDP Bloom gate applies only when admitting a new UDP flow */
    if (is_udp) {
      if (!udp_admission_allowed(&key, &st_udp_bloom_refused)) return;
    }

    /* Insert like HashFlow: try h1 empty else h2 empty else go to A[g] overwrite */
    if (!T[p1].in_use) {
      init_new_entry(&T[p1], key, sip, dip, sport, dport, proto);
      st_inserted_T++;
      e = &T[p1];
      if (is_udp) tw_insert_generic(T, tw_head_T, (int)p1, tv->tv_sec + UDP_IDLE_SEC);
    } else if (!T[p2].in_use) {
      init_new_entry(&T[p2], key, sip, dip, sport, dport, proto);
      st_inserted_T++;
      e = &T[p2];
      if (is_udp) tw_insert_generic(T, tw_head_T, (int)p2, tv->tv_sec + UDP_IDLE_SEC);
    } else {
      /* overwrite A[g] */
      if (is_udp && A[ga].in_use) tw_remove_generic(A, tw_head_A, (int)ga);
      init_new_entry(&A[ga], key, sip, dip, sport, dport, proto);
      st_inserted_A++;
      e = &A[ga];
      if (is_udp) tw_insert_generic(A, tw_head_A, (int)ga, tv->tv_sec + UDP_IDLE_SEC);
    }
  }

  /* Track packet into chosen entry */
  append_packet(e, tv, sip, sport, ip_len);

  /* UDP: refresh idle timer (both T and A entries) */
  if (is_udp) {
    if (e >= T && e < T + TABLE_SIZE) {
      int idx = (int)(e - T);
      tw_insert_generic(T, tw_head_T, idx, tv->tv_sec + UDP_IDLE_SEC);
    } else if (e >= A && e < A + AUX_SIZE) {
      int idx = (int)(e - A);
      tw_insert_generic(A, tw_head_A, idx, tv->tv_sec + UDP_IDLE_SEC);
    }
  }

  /* Flush on FLOW_CAP or FIN (TCP) */
  if (e->count == FLOW_CAP || (!is_udp && tcp_fin)) {
    if (is_udp) {
      if (e >= T_udp && e < T_udp + TABLE_SIZE) {
        dump_and_clear_udp(T_udp, tw_head_T_udp, (int)(e - T_udp), "flow_output_hashflow_udp.csv");
      } else {
        dump_and_clear_udp(A_udp, tw_head_A_udp, (int)(e - A_udp), "flow_output_hashflow_udp.csv");
      }
    } else {
      if (e >= T_tcp && e < T_tcp + TABLE_SIZE) {
        dump_and_clear_tcp(T_tcp, (int)(e - T_tcp), "flow_output_hashflow_tcp.csv");
      } else {
        dump_and_clear_tcp(A_tcp, (int)(e - A_tcp), "flow_output_hashflow_tcp.csv");
      }
    }
    return;
  }

  /* Promotion logic (non-SYN path) — mirrors the pseudocode structure: :contentReference[oaicite:2]{index=2}
     - choose pos = argmin(T[h1(id)].pcks, T[h2(id)].pcks) (treat empty as 0)
     - if A[g(id)].pcks > min then move A -> T[pos]
     - handle possible eviction from T[pos] by relocating to alternate slot or A */
  {
    /* pick pos among p1/p2 with smaller packet count */
    uint32_t pos = p1;
    int min = T[p1].in_use ? T[p1].count : 0;
    int v2  = T[p2].in_use ? T[p2].count : 0;
    if (v2 < min) { pos = p2; min = v2; }

    if (A[ga].in_use && A[ga].count > min) {
      flow_entry_t promoted = A[ga];
      flow_entry_t evicted  = T[pos];

      /* remove UDP wheel hooks before overwriting */
      if (is_udp) {
        if (T[pos].in_use) tw_remove_generic(T, tw_head_T, (int)pos);
        tw_remove_generic(A, tw_head_A, (int)ga);
      }

      /* promote */
      T[pos] = promoted;
      st_promoted_A_to_T++;

      /* clear aux slot */
      memset(&A[ga], 0, sizeof A[ga]);
      A[ga].tw_slot = A[ga].tw_next = A[ga].tw_prev = -1;

      /* reinsert UDP wheel for promoted main entry */
      if (is_udp) tw_insert_generic(T, tw_head_T, (int)pos, tv->tv_sec + UDP_IDLE_SEC);

      /* if eviction happened, try relocate */
      if (evicted.in_use) {
        relocate_or_aux(T, Tmask, A, Amask, evicted, is_udp, tw_head_T, tw_head_A, tv->tv_sec);
      }
    }
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
  int syn = 0, fin = 0;

  int ip_hl = ip->ip_hl * 4;

  if (proto == IPPROTO_TCP) {
    const struct tcphdr *th = (const struct tcphdr *)(pkt + sizeof *eth + ip_hl);
    sport = ntohs(th->th_sport);
    dport = ntohs(th->th_dport);
    syn = (th->th_flags & TH_SYN) != 0;
    fin = (th->th_flags & TH_FIN) != 0;
  } else if (proto == IPPROTO_UDP) {
    const struct udphdr *uh = (const struct udphdr *)(pkt + sizeof *eth + ip_hl);
    sport = ntohs(uh->uh_sport);
    dport = ntohs(uh->uh_dport);
  } else {
    return 0;
  }

  last_pcap_sec = h->ts.tv_sec;
  track_packet(&h->ts, sip, dip, sport, dport, proto, syn, fin, ntohs(ip->ip_len));
  return 1;
}

/* ================================================================= */
/*                                main                               */
/* ================================================================= */
int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s file.pcap\n", argv[0]);
    return 1;
  }

  /* init bloom + wheel */
  udp_bloom_clear();
  for (int i = 0; i < TW_SLOTS; ++i) { tw_head_T_udp[i] = -1; tw_head_A_udp[i] = -1; }

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

  /* flush remaining TCP/UDP entries (both T and A) */
  for (int i = 0; i < TABLE_SIZE; ++i) {
    if (T_tcp[i].in_use) dump_and_clear_tcp(T_tcp, i, "flow_output_hashflow_tcp.csv");
    if (T_udp[i].in_use) dump_and_clear_udp(T_udp, tw_head_T_udp, i, "flow_output_hashflow_udp.csv");
  }
  for (int i = 0; i < AUX_SIZE; ++i) {
    if (A_tcp[i].in_use) dump_and_clear_tcp(A_tcp, i, "flow_output_hashflow_tcp.csv");
    if (A_udp[i].in_use) dump_and_clear_udp(A_udp, tw_head_A_udp, i, "flow_output_hashflow_udp.csv");
  }

  pthread_mutex_lock(&mtx);
  exiting = 1;
  pthread_cond_broadcast(&cond_full);
  pthread_mutex_unlock(&mtx);

  fprintf(stderr, "main: setting exiting=1 and joining sender (fill=%zu)\n", fill);
  pthread_join(zmq_thread, NULL);

  pcap_close(pc);

  fprintf(stderr,
          "stats:"
          " inserted_T=%" PRIu64
          " inserted_A=%" PRIu64
          " matched=%" PRIu64
          " pkts_tracked=%" PRIu64
          " promoted_A_to_T=%" PRIu64
          " evicted_T_to_A=%" PRIu64
          " udp_bloom_refused=%" PRIu64
          "\n",
          st_inserted_T,
          st_inserted_A,
          st_matched,
          st_packets_tracked,
          st_promoted_A_to_T,
          st_evicted_T_to_A,
          st_udp_bloom_refused);

  return 0;
}
