/*********************************************************************
 *  flowhash_zmq_timing_wheel_with_prediction.c
 *
 *  Restored core system:
 *   - Timing wheel UDP idle flush
 *   - TCP FIN+FIN (only flush at FLOW_CAP, per original)
 *   - JSON encode + ZMQ batch push sender thread
 *   - Optional CSV logging
 *
 *  New additions:
 *   - Auxiliary contender table per bucket to track colliding flows until FIRST_N
 *   - Contention-aware ML duel resolution using tl2cgen predict() at FIRST_N=8
 *   - No eviction unless a contender exists
 *   - Duel rules A/B/C + swap rule
 *
 *********************************************************************/

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <inttypes.h>
#include <jansson.h>
#include <signal.h>
#include <math.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <zmq.h>
#include <unistd.h>
/* tl2cgen header */
#include "../rf_first8_40packets_build/header.h"

/* ---------- parameters ------------------------------------------- */
#define TABLE_SIZE (65536 * 2) /* must be power of 2 */
#define FLOW_CAP 40            /* pkts per flow      */
#define FIRST_N 8              /* packets used by model */
#define UDP_IDLE_SEC 30        /* idle timeout UDP   */
#define TW_SLOTS 256           /* must be power of 2 */
#define BUF_MAX 64             /* ring buffer slots  */
#define BATCH_SIZE 16          /* flows per JSON msg */
#define SHOW_OUTPUT 0          /* stderr debug prints */
#define WRITE_TO_CSV 1

/* ML gate */
#define EVICT_THRESHOLD 0.50   /* threshold for yes/no */

/* ZMQ shutdown / blocking behavior */
#define ZMQ_LINGER_MS 0
#define ZMQ_SNDTIMEO_MS 100 /* set 0 for "don't wait" or keep small */
#define ZMQ_ENDPOINT "ipc:///tmp/flowpipe"

/* compile-time guards */
#if (TABLE_SIZE & (TABLE_SIZE - 1)) != 0
#error "TABLE_SIZE must be a power of two"
#endif

#if (TW_SLOTS & (TW_SLOTS - 1)) != 0
#error "TW_SLOTS must be a power of two"
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
  int fin_cli_done, fin_srv_done;

  struct timeval ts[FLOW_CAP];
  int32_t len[FLOW_CAP];  /* sign encodes direction, magnitude is ip_len */
  int count;

  /* --- timing-wheel bookkeeping --- */
  int tw_next;
  int tw_slot;
} flow_entry_t;

/* main table + aux contender table (1 contender per bucket) */
static flow_entry_t table[TABLE_SIZE] = {0};
static flow_entry_t aux[TABLE_SIZE]   = {0};

static inline int idx_of(flow_entry_t *base, flow_entry_t *e) { return (int)(e - base); }

/* ---------- timing-wheel data ------------------------------------ */
/* We keep two wheels: one for main table, one for aux.
   This preserves UDP expiry correctness for both. */
static int tw_head_main[TW_SLOTS];
static int tw_head_aux[TW_SLOTS];

static time_t tw_now_sec = 0;
static int tw_now_slot = 0;
static int tw_initialised = 0;
static time_t last_pcap_sec = 0;

/* ---------- stats ------------------------------------------------- */
static uint64_t st_flows_inserted = 0;
static uint64_t st_flows_matched  = 0;
static uint64_t st_packets_tracked = 0;

static uint64_t st_aux_inserted = 0;
static uint64_t st_aux_matched  = 0;
static uint64_t st_aux_third_dropped = 0;

static uint64_t st_duels = 0;
static uint64_t st_swaps = 0;
static uint64_t st_main_wins = 0;
static uint64_t st_aux_wins  = 0;
static volatile sig_atomic_t g_dump_requested = 0;
static volatile sig_atomic_t g_sigquit_dump_full = 0;
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
static void dump_active_flows(time_t now_sec);
/* ================================================================= */
/*                           Timing-wheel                            */
/* ================================================================= */

static void tw_init(time_t start_sec) {
  for (int i = 0; i < TW_SLOTS; ++i) {
    tw_head_main[i] = -1;
    tw_head_aux[i]  = -1;
  }
  tw_now_sec = start_sec;
  tw_now_slot = (int)(start_sec % TW_SLOTS);
  tw_initialised = 1;
}

/* Generic wheel remove/insert operating on a base table + wheel head list. */
static void tw_remove_generic(flow_entry_t *base, int *tw_head, int idx) {
  flow_entry_t *e = &base[idx];
  if (e->tw_slot < 0) return;

  int slot = e->tw_slot;
  int cur = tw_head[slot];
  int prev = -1;
  while (cur != -1 && cur != idx) {
    prev = cur;
    cur = base[cur].tw_next;
  }

  if (cur == -1) {
    e->tw_slot = e->tw_next = -1;
    return;
  }

  if (prev == -1)
    tw_head[slot] = base[cur].tw_next;
  else
    base[prev].tw_next = base[cur].tw_next;

  e->tw_slot = e->tw_next = -1;
}

static void tw_insert_generic(flow_entry_t *base, int *tw_head, int idx, time_t exp_sec) {
  flow_entry_t *e = &base[idx];
  if (e->tw_slot >= 0) tw_remove_generic(base, tw_head, idx);

  int slot = (int)(exp_sec % TW_SLOTS);
  e->tw_slot = slot;
  e->tw_next = tw_head[slot];
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

  pthread_cond_signal(&cond_full);  // signal on every enqueue
  pthread_mutex_unlock(&mtx);
}

static void *sender_thread(void *arg) {
  (void)arg;

  void *ctx = zmq_ctx_new();
  void *sock = zmq_socket(ctx, ZMQ_PUSH);

  int linger = ZMQ_LINGER_MS;
  zmq_setsockopt(sock, ZMQ_LINGER, &linger, sizeof(linger));

  /* Optional: keep your sndtimeo, but we’ll also use DONTWAIT so we never hang */
  int sndtimeo = ZMQ_SNDTIMEO_MS;
  zmq_setsockopt(sock, ZMQ_SNDTIMEO, &sndtimeo, sizeof(sndtimeo));

  if (zmq_bind(sock, ZMQ_ENDPOINT) != 0) {
    fprintf(stderr, "zmq_bind(%s) failed: %s\n", ZMQ_ENDPOINT, zmq_strerror(errno));
    zmq_close(sock);
    zmq_ctx_term(ctx);
    return NULL;
  }

  for (;;) {
    /* ---- wait for work or shutdown ---- */
    pthread_mutex_lock(&mtx);
    while (fill == 0 && !exiting) {
      pthread_cond_wait(&cond_full, &mtx);
    }

    if (exiting && fill == 0) {
      pthread_mutex_unlock(&mtx);
      break; /* clean exit */
    }

    /* ---- build a batch (drain up to BATCH_SIZE) ---- */
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

    /* ---- send without ever blocking ---- */
    if (json_array_size(batch) > 0) {
      char *txt = json_dumps(batch, JSON_COMPACT);
      int rc = zmq_send(sock, txt, strlen(txt), ZMQ_DONTWAIT);
      (void)rc; /* optionally inspect rc / errno */
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

static inline int coinflip(void) {
  return rand() & 1;
}

static inline double tv_to_sec(const struct timeval *tv) {
  return (double)tv->tv_sec + (double)tv->tv_usec / 1e6;
}

static inline double dabs(double x) { return x < 0 ? -x : x; }

/* ================================================================= */
/*                         CSV logging (unchanged)                    */
/* ================================================================= */
static void write_to_csv(flow_entry_t *e) {
  if (e->count != FLOW_CAP) return;

  char ip_small[INET_ADDRSTRLEN], ip_large[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &e->key.ip1, ip_small, sizeof(ip_small));
  inet_ntop(AF_INET, &e->key.ip2, ip_large, sizeof(ip_large));

  char input_field[256];
  snprintf(input_field, sizeof(input_field), "%s%d%s%d%s", ip_small, e->key.port1,
           ip_large, e->key.port2, e->is_udp ? "UDP" : "TCP");

  char feature_vector[4096];
  size_t w = 0;
  w += (size_t)snprintf(feature_vector + w, sizeof(feature_vector) - w, "[");

  double ts_0 = e->ts[0].tv_sec + e->ts[0].tv_usec / 1e6;
  for (int i = 0; i < e->count; ++i) {
    double ts = e->ts[i].tv_sec + e->ts[i].tv_usec / 1e6;
    double offset = ts - ts_0;
    if (e->len[i] < 0) offset *= -1;

    w += (size_t)snprintf(feature_vector + w, sizeof(feature_vector) - w,
                          "(%.6f, %.1f)%s", offset, (double)e->len[i],
                          (i < e->count - 1) ? ", " : "");
    if (w >= sizeof(feature_vector)) break;
  }

  if (w < sizeof(feature_vector))
    (void)snprintf(feature_vector + w, sizeof(feature_vector) - w, "]");

  FILE *f = fopen("flow_output_timing_wheel_zmq.csv", "a");
  if (!f) { perror("fopen"); exit(1); }
  fprintf(f, "%s,\"%s\"\n", input_field, feature_vector);
  fclose(f);
}

/* ================================================================= */
/*                     flow finalisation & output                     */
/* ================================================================= */
static void dump_and_clear_main(flow_entry_t *e) {
  /* remove from main wheel if present */
  int idx = idx_of(table, e);
  tw_remove_generic(table, tw_head_main, idx);

  if (WRITE_TO_CSV) write_to_csv(e);

  if (SHOW_OUTPUT) {
    char ca[INET_ADDRSTRLEN], sa[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->cli_ip, ca, sizeof ca);
    inet_ntop(AF_INET, &e->srv_ip, sa, sizeof sa);
    fprintf(stderr, "Flow %s:%u ↔ %s:%u %s pkts:%d\n",
            ca, e->cli_port, sa, e->srv_port, e->is_udp ? "UDP" : "TCP", e->count);
  }

  enqueue_flow(e);

  memset(e, 0, sizeof *e);
  e->tw_slot = e->tw_next = -1;
}

/* Aux flows: we generally DROP on expiration / losing duel (no output). */
static void drop_and_clear_aux(flow_entry_t *e) {
  int idx = idx_of(aux, e);
  tw_remove_generic(aux, tw_head_aux, idx);
  memset(e, 0, sizeof *e);
  e->tw_slot = e->tw_next = -1;
}

/* ================================================================= */
/*                 timing-wheel advance logic                         */
/* ================================================================= */
static void expire_slot_lists(int slot) {
  /* expire main */
  int idx = tw_head_main[slot];
  tw_head_main[slot] = -1;
  while (idx != -1) {
    int nxt = table[idx].tw_next;
    table[idx].tw_slot = table[idx].tw_next = -1;
    dump_and_clear_main(&table[idx]);
    idx = nxt;
  }

  /* expire aux */
  idx = tw_head_aux[slot];
  tw_head_aux[slot] = -1;
  while (idx != -1) {
    int nxt = aux[idx].tw_next;
    aux[idx].tw_slot = aux[idx].tw_next = -1;
    drop_and_clear_aux(&aux[idx]);
    idx = nxt;
  }
}

static void tw_advance(time_t now_sec) {
  if (!tw_initialised) tw_init(now_sec);

  if (now_sec <= tw_now_sec) return;

  time_t delta = now_sec - tw_now_sec;
  if (delta > 10) {
    fprintf(stderr, "tw_advance: tw_now_sec=%ld now_sec%ld delta=%ld\n",
                  (long)tw_now_sec, (long)now_sec, (long)delta);
  }
  /* BIG JUMP: if we jumped >= full wheel, everything expires */
  if (delta >= TW_SLOTS) {
    for (int s = 0; s < TW_SLOTS; ++s) {
      expire_slot_lists(s);
    }
    tw_now_sec  = now_sec;
    tw_now_slot = (int)(now_sec % TW_SLOTS);
    return;
  }

  /* SMALL JUMP: step normally */
  while (tw_now_sec < now_sec) {
    tw_now_sec++;
    tw_now_slot = (tw_now_slot + 1) & (TW_SLOTS - 1);
    expire_slot_lists(tw_now_slot);
  }
}

/* ================================================================= */
/*                 ML feature extraction (matches training)           */
/* ================================================================= */

static void stats_1d(const double *a, int n,
                     double *out_mean, double *out_std,
                     double *out_min, double *out_max, double *out_sum) {
  double sum = 0.0;
  double mn = a[0], mx = a[0];
  for (int i = 0; i < n; i++) {
    double v = a[i];
    sum += v;
    if (v < mn) mn = v;
    if (v > mx) mx = v;
  }
  double mean = sum / (double)n;

  double var = 0.0;
  for (int i = 0; i < n; i++) {
    double d = a[i] - mean;
    var += d * d;
  }
  var /= (double)n; /* numpy.std default (population) */
  double std = (var > 0.0) ? sqrt(var) : 0.0;

  *out_mean = mean;
  *out_std  = std;
  *out_min  = mn;
  *out_max  = mx;
  *out_sum  = sum;
}

static int build_feature_entries_first8(const flow_entry_t *e, union Entry *x, int32_t nfeat) {
  if (e->count < FIRST_N) return 0;
  if (nfeat != 27) return 0;

  /* First 8 packets are already in global pcap time order */
  double t[8], s[8];
  for (int i = 0; i < 8; i++) {
    t[i] = tv_to_sec(&e->ts[i]);
    s[i] = dabs((double)e->len[i]); /* training used positive sizes */
  }

  double dt[7];
  for (int i = 0; i < 7; i++) dt[i] = t[i + 1] - t[i];

  double span = t[7] - t[0];
  const double eps = 1e-9;

  double mean_size, std_size, min_size, max_size, sum_size;
  stats_1d(s, 8, &mean_size, &std_size, &min_size, &max_size, &sum_size);

  double mean_dt, std_dt, min_dt, max_dt, sum_dt;
  stats_1d(dt, 7, &mean_dt, &std_dt, &min_dt, &max_dt, &sum_dt);

  double pps_8 = 8.0 / (span + eps);
  double bps_8 = sum_size / (span + eps);

  for (int i = 0; i < nfeat; i++) {
    x[i].missing = 0;
    x[i].fvalue = 0.0;
  }

  /* Order must match your Python dict insertion order for N=8:
     s1..s8, dt2..dt8,
     mean_size,std_size,min_size,max_size,sum_size,
     mean_dt,std_dt,min_dt,max_dt,span_8,pps_8,bps_8
  */
  int k = 0;

  for (int i = 0; i < 8; i++) x[k++].fvalue = s[i];
  for (int i = 0; i < 7; i++) x[k++].fvalue = dt[i];

  x[k++].fvalue = mean_size;
  x[k++].fvalue = std_size;
  x[k++].fvalue = min_size;
  x[k++].fvalue = max_size;
  x[k++].fvalue = sum_size;

  x[k++].fvalue = mean_dt;
  x[k++].fvalue = std_dt;
  x[k++].fvalue = min_dt;
  x[k++].fvalue = max_dt;
  x[k++].fvalue = span;

  x[k++].fvalue = pps_8;
  x[k++].fvalue = bps_8;

  return (k == nfeat);
}

static inline double score_reach40(const flow_entry_t *e) {
  int32_t nfeat = get_num_feature(); /* should be 27 */
  union Entry xbuf[32];
  if (nfeat != 27) return 1.0; /* fail-open */

  if (!build_feature_entries_first8(e, xbuf, nfeat)) return 1.0;

  double out[1] = {0.0};
  predict(xbuf, /*pred_margin=*/0, out);
  postprocess(out);
  return out[0];
}

static inline int keep_yesno(const flow_entry_t *e) {
  double p = score_reach40(e);
  return (p >= EVICT_THRESHOLD);
}

/* ================================================================= */
/*                 Contention resolution (duels)                      */
/* ================================================================= */

static void reschedule_udp_if_needed(flow_entry_t *base, int *tw_head, flow_entry_t *e, time_t now_sec) {
  if (!e->in_use) return;
  if (!e->is_udp) return;
  int idx = idx_of(base, e);
  tw_insert_generic(base, tw_head, idx, now_sec + UDP_IDLE_SEC);
}

/* Swap main<->aux, fixing wheel memberships */
static void swap_main_aux_bucket(uint32_t p, time_t now_sec) {
  flow_entry_t tmp = table[p];
  table[p] = aux[p];
  aux[p] = tmp;

  /* After swap, their tw_slot pointers belong to wrong wheel lists. Reset and reinsert if UDP. */
  table[p].tw_slot = table[p].tw_next = -1;
  aux[p].tw_slot   = aux[p].tw_next   = -1;

  reschedule_udp_if_needed(table, tw_head_main, &table[p], now_sec);
  reschedule_udp_if_needed(aux,   tw_head_aux,  &aux[p],   now_sec);

  st_swaps++;
}

static void resolve_duel_bucket(uint32_t p, time_t now_sec) {
  flow_entry_t *m = &table[p];
  flow_entry_t *a = &aux[p];
  if (!m->in_use || !a->in_use) return;

  /* 2b) If aux reached 8 and main not, swap them */
  if (a->count >= FIRST_N && m->count < FIRST_N) {
    swap_main_aux_bucket(p, now_sec);
    return;
  }

  /* 2a) If both reached 8, score and decide */
  if (m->count >= FIRST_N && a->count >= FIRST_N) {
    st_duels++;

    int m_keep = keep_yesno(m);
    int a_keep = keep_yesno(a);

    int keep_main;
    if (m_keep && !a_keep) keep_main = 1;         /* A */
    else if (!m_keep && a_keep) keep_main = 0;    /* A */
    else keep_main = coinflip();                  /* B or C */

    if (!keep_main) {
      swap_main_aux_bucket(p, now_sec);
      st_aux_wins++;
    } else {
      st_main_wins++;
    }

    /* drop loser (now in aux[p]) */
    drop_and_clear_aux(&aux[p]);
  }
}

/* ================================================================= */
/*                 packet tracking (called per packet)               */
/* ================================================================= */

static void init_new_entry(flow_entry_t *e, flow_key_t key,
                           uint32_t sip, uint32_t dip,
                           uint16_t sport, uint16_t dport,
                           uint8_t proto) {
  memset(e, 0, sizeof *e);
  e->in_use = 1;
  e->key = key;
  e->is_udp = (proto == IPPROTO_UDP);

  e->cli_ip = sip;
  e->srv_ip = dip;
  e->cli_port = sport;
  e->srv_port = dport;

  e->tw_slot = e->tw_next = -1;
}

static void track_packet(const struct timeval *tv, uint32_t sip, uint32_t dip,
                         uint16_t sport, uint16_t dport, uint8_t proto,
                         int tcp_syn, int tcp_fin, uint16_t ip_len) {
  if (g_sigquit_dump_full) {
  g_sigquit_dump_full = 0;

  int main_cnt = 0, aux_cnt = 0;
  int main_udp = 0, aux_udp = 0;
  int main_tcp = 0, aux_tcp = 0;

  for (int i = 0; i < TABLE_SIZE; i++) {
    if (table[i].in_use) {
      main_cnt++;
      if (table[i].is_udp) main_udp++; else main_tcp++;
    }
    if (aux[i].in_use) {
      aux_cnt++;
      if (aux[i].is_udp) aux_udp++; else aux_tcp++;
    }
  }

  fprintf(stderr,
    "ACTIVE: main=%d (udp=%d tcp=%d) aux=%d (udp=%d tcp=%d)\n",
    main_cnt, main_udp, main_tcp, aux_cnt, aux_udp, aux_tcp);
 }
  tw_advance(tv->tv_sec);

  flow_key_t key = make_key(sip, dip, sport, dport, proto);

  char kbuf[64];
  snprintf(kbuf, sizeof kbuf, "%08x%04x%08x%04x%02x",
           key.ip1, key.port1, key.ip2, key.port2, key.proto);
  uint32_t h = fnv1a_32(kbuf);
  uint32_t p = h & (TABLE_SIZE - 1);

  flow_entry_t *m = &table[p];
  flow_entry_t *a = &aux[p];

  /* Determine whether packet belongs to main, aux, or is a new contender */
  flow_entry_t *e = NULL;
  int is_new = 0;
  int is_aux = 0;

  if (!m->in_use) {
    e = m; is_new = 1; is_aux = 0;
  } else if (!compare_key(&m->key, &key)) {
    e = m; is_new = 0; is_aux = 0;
  } else {
    /* collision with main */
    if (!a->in_use) {
      e = a; is_new = 1; is_aux = 1;
    } else if (!compare_key(&a->key, &key)) {
      e = a; is_new = 0; is_aux = 1;
    } else {
      /* third contender */
      st_aux_third_dropped++;
      return;
    }
  }

  if (is_new) {
    /* no mid-flow TCP for new flows */
    if (proto == IPPROTO_TCP && !tcp_syn) return;

    init_new_entry(e, key, sip, dip, sport, dport, proto);
    if (is_aux) st_aux_inserted++;
    else st_flows_inserted++;
  } else {
    if (is_aux) st_aux_matched++;
    else st_flows_matched++;
  }

  /* Track packet */
  if (e->count < FLOW_CAP) {
    int from_cli = (sip == e->cli_ip && sport == e->cli_port);
    e->ts[e->count] = *tv;
    e->len[e->count] = (from_cli ? +1 : -1) * (int32_t)ip_len;
    e->count++;
    st_packets_tracked++;
  }

  /* UDP: reschedule based on whichever table it is in */
  if (e->is_udp) {
    if (is_aux) tw_insert_generic(aux, tw_head_aux, (int)p, tv->tv_sec + UDP_IDLE_SEC);
    else        tw_insert_generic(table, tw_head_main, (int)p, tv->tv_sec + UDP_IDLE_SEC);
  }

  /* If main reaches FLOW_CAP, flush it (same behavior as original for “tracked flows”). */
  if (!is_aux && e->count == FLOW_CAP) {
    dump_and_clear_main(e);
    return;
  }

  /* Contention-aware ML arbitration */
  if (m->in_use && a->in_use) {
    resolve_duel_bucket(p, tv->tv_sec);
  }
}

/* ================================================================= */
/*                parse Ethernet/IP/TCP/UDP & call tracker            */
/* ================================================================= */
static int parse_and_track(const struct pcap_pkthdr *h, const u_char *pkt) {

  /* ---- DEBUG: detect large timestamp jumps ---- */
  static time_t prev = 0;
  if (prev && h->ts.tv_sec - prev > 10) {
    fprintf(stderr, "TS JUMP %ld -> %ld (Δ=%ld)\n",
            (long)prev,
            (long)h->ts.tv_sec,
            (long)(h->ts.tv_sec - prev));
  }
  prev = h->ts.tv_sec;
  /* -------------------------------------------- */
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
static void on_sigquit(int sig) {
  (void)sig;
  g_sigquit_dump_full = 1;

  char buf[256];
  int n = snprintf(buf, sizeof(buf),
    "\n=== SIGQUIT RECEIVED ===\n"
    "tw_now_sec=%ld tw_now_slot=%d\n"
    "ZMQ fill=%zu exiting=%d\n",
    (long)tw_now_sec, tw_now_slot, fill, exiting);
  if (n > 0) (void)write(STDERR_FILENO, buf, (size_t)n);
}

static void dump_active_flows(time_t now_sec) {
  int main_cnt = 0, aux_cnt = 0;
  int main_udp = 0, aux_udp = 0;

  fprintf(stderr, "\n=== DUMP ACTIVE FLOWS (now=%ld, tw_now=%ld slot=%d) ===\n",
          (long)now_sec, (long)tw_now_sec, tw_now_slot);

  /* show up to N examples so output stays readable */
  int shown = 0;
  const int MAX_SHOW = 50;

  for (int i = 0; i < TABLE_SIZE; ++i) {
    if (table[i].in_use) {
      main_cnt++;
      if (table[i].is_udp) main_udp++;

      if (shown < MAX_SHOW) {
        char ca[INET_ADDRSTRLEN], sa[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &table[i].cli_ip, ca, sizeof ca);
        inet_ntop(AF_INET, &table[i].srv_ip, sa, sizeof sa);

        fprintf(stderr,
                "MAIN[%d] %s:%u ↔ %s:%u %s cnt=%d tw_slot=%d fin=%d/%d\n",
                i, ca, table[i].cli_port, sa, table[i].srv_port,
                table[i].is_udp ? "UDP" : "TCP",
                table[i].count, table[i].tw_slot,
                table[i].fin_cli_done, table[i].fin_srv_done);
        shown++;
      }
    }

    if (aux[i].in_use) {
      aux_cnt++;
      if (aux[i].is_udp) aux_udp++;
    }
  }

  fprintf(stderr, "Totals: main=%d (udp=%d) aux=%d (udp=%d)\n",
          main_cnt, main_udp, aux_cnt, aux_udp);
  fprintf(stderr, "ZMQ buffer: fill=%zu head=%zu tail=%zu exiting=%d\n",
          fill, head, tail, exiting);
  fprintf(stderr, "=== END DUMP ===\n\n");
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

  /* sanity: model expects 27 features for first_n=8 */
  if (get_num_feature() != 27) {
    fprintf(stderr, "ERROR: model expects %d features, but this program assumes 27 (first_n=8)\n",
            (int)get_num_feature());
    return 1;
  }

  srand((unsigned)time(NULL));

  char err[PCAP_ERRBUF_SIZE];
  fprintf(stderr, "main: starting\n");
  pcap_t *pc = pcap_open_offline(argv[1], err);
  if (!pc) {
    fprintf(stderr, "pcap_open: %s\n", err);
    return 1;
  }
  fprintf(stderr, "main: pcap opened\n");
  /* start sender thread */
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

  /* final flush: advance far enough to expire everything */
  if (last_pcap_sec != 0) {
    tw_advance(last_pcap_sec + UDP_IDLE_SEC + TW_SLOTS);
  }

  /* flush anything still in table (main only, as original behavior) */
  for (int i = 0; i < TABLE_SIZE; ++i) {
    if (table[i].in_use) dump_and_clear_main(&table[i]);
  }
  /* drop remaining aux silently */
  for (int i = 0; i < TABLE_SIZE; ++i) {
    if (aux[i].in_use) drop_and_clear_aux(&aux[i]);
  }

  /* shut down sender thread */
  pthread_mutex_lock(&mtx);
  exiting = 1;
  pthread_cond_broadcast(&cond_full);
  pthread_mutex_unlock(&mtx);
  fprintf(stderr, "main: setting exiting=1 and joining sender (fill=%zu)\n", fill);
  pthread_join(zmq_thread, NULL);

  pcap_close(pc);

  fprintf(stderr,
          "stats: main_inserted=%" PRIu64 " main_matched=%" PRIu64
          " aux_inserted=%" PRIu64 " aux_matched=%" PRIu64 " aux_third_dropped=%" PRIu64
          " pkts_tracked=%" PRIu64
          " duels=%" PRIu64 " swaps=%" PRIu64 " main_wins=%" PRIu64 " aux_wins=%" PRIu64 "\n",
          st_flows_inserted, st_flows_matched,
          st_aux_inserted, st_aux_matched, st_aux_third_dropped,
          st_packets_tracked,
          st_duels, st_swaps, st_main_wins, st_aux_wins);

  return 0;
}
