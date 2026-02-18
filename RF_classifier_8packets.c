/*********************************************************************
 *  flowhash_zmq_timing_wheel_with_prediction_two_tables_bloom.c
 *
 *  MODIFIED (Feb 2026):
 *   - Uses embedded Python + joblib sklearn model for keep/evict decisions
 *     (predict_proba for class=1).
 *
 *  UPDATED (per your request):
 *   - Adds CSV outputs like your weighted_random_chance_bloom_seeded.c:
 *       1) Per-flow feature-vector dump at FLOW_CAP (already present)
 *       2) collision events logged to a .bin during runtime, then converted to:
 *            joblib_two_tables_collisions.csv
 *       3) ground-truth per-flow summary CSV:
 *            joblib_two_tables_flow_collision_summary.csv
 *
 *  NEW usage:
 *     ./flowhash_with_joblib file.pcap model.joblib
 *
 *  Expected Python module in working dir (or PYTHONPATH):
 *     joblib_predict.py with:
 *       init(model_path: str, expected_n: int=27) -> True
 *       predict_proba_1(x_list: list[float]) -> float   # p(class=1)
 *
 *  Build (example):
 *     gcc -O2 -Wall -Wextra -pthread \
 *       flowhash_zmq_timing_wheel_with_prediction_two_tables_bloom.c \
 *       $(python3-config --cflags) $(python3-config --ldflags) \
 *       -lpcap -lzmq -ljansson -lm -o flowhash_with_joblib
 *********************************************************************/

#define _DEFAULT_SOURCE
#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <jansson.h>
#include <math.h>
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
#define TABLE_SIZE (4096) /* must be power of 2 */
#define FLOW_CAP 40
#define FIRST_N 8
#define NFEAT 27
#define UDP_IDLE_SEC 30
#define TW_SLOTS 256 /* must be power of 2 */
#define BUF_MAX 64
#define BATCH_SIZE 16
#define SHOW_OUTPUT 0
#define WRITE_TO_CSV 1

#define UDP_MAIN_SIZE (TABLE_SIZE)
#define UDP_AUX_SIZE (TABLE_SIZE)
#define TCP_MAIN_SIZE (TABLE_SIZE)
#define TCP_AUX_SIZE (TABLE_SIZE)

/* ML gate */
#define EVICT_THRESHOLD 0.50

/* ZMQ shutdown / blocking behavior */
#define ZMQ_LINGER_MS 0
#define ZMQ_SNDTIMEO_MS 100
#define ZMQ_ENDPOINT "ipc:///tmp/flowpipe"

/* ---------- UDP Bloom filter (UDP-only admission gate) ------------ */
#define UDP_BLOOM_BITS (1u << 28) /* 134,217,728 bits (~16 MB) */
#define UDP_BLOOM_BYTES (UDP_BLOOM_BITS / 8u)
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
#if (UDP_AUX_SIZE & (UDP_AUX_SIZE - 1)) != 0
#error "UDP_AUX_SIZE must be a power of two"
#endif
#if (TCP_AUX_SIZE & (TCP_AUX_SIZE - 1)) != 0
#error "TCP_AUX_SIZE must be a power of two"
#endif

/* ================================================================= */
/*                 Embedded Python / joblib bridge                    */
/* ================================================================= */

/*
 * We import python module "joblib_predict" with:
 *   init(model_path: str, expected_n: int=27) -> True
 *   predict_proba_1(x_list: list[float]) -> float  # p(class=1)
 */
static int g_py_inited = 0;
static PyObject *g_py_mod = NULL;
static PyObject *g_py_init_fn = NULL;
static PyObject *g_py_pred_fn = NULL;

static int ml_joblib_init(const char *model_path) {
  if (g_py_inited)
    return 1;

  Py_Initialize();
  if (!Py_IsInitialized()) {
    fprintf(stderr, "ERROR: Py_Initialize failed\n");
    return 0;
  }

  /* ensure CWD is importable */
  PyRun_SimpleString("import sys; sys.path.insert(0, '')");

  g_py_mod = PyImport_ImportModule("joblib_predict");
  if (!g_py_mod) {
    PyErr_Print();
    fprintf(stderr, "ERROR: failed to import python module 'joblib_predict'\n");
    return 0;
  }

  g_py_init_fn = PyObject_GetAttrString(g_py_mod, "init");
  g_py_pred_fn = PyObject_GetAttrString(g_py_mod, "predict_proba_1");
  if (!g_py_init_fn || !PyCallable_Check(g_py_init_fn) || !g_py_pred_fn || !PyCallable_Check(g_py_pred_fn)) {
    PyErr_Print();
    fprintf(stderr, "ERROR: joblib_predict.init or joblib_predict.predict_proba_1 missing/not callable\n");
    return 0;
  }

  /* call init(model_path, expected_n=27) */
  PyObject *args = Py_BuildValue("(si)", model_path, (int)NFEAT);
  PyObject *ret = PyObject_CallObject(g_py_init_fn, args);
  Py_XDECREF(args);

  if (!ret) {
    PyErr_Print();
    fprintf(stderr, "ERROR: joblib_predict.init() failed for model '%s'\n", model_path);
    return 0;
  }
  Py_DECREF(ret);

  g_py_inited = 1;
  return 1;
}

static double ml_joblib_predict_proba1(const double *x, size_t n) {
  if (!g_py_inited || !g_py_pred_fn || !x || n != (size_t)NFEAT)
    return 1.0;

  PyObject *list = PyList_New((Py_ssize_t)n);
  if (!list) {
    PyErr_Print();
    return 1.0;
  }

  for (size_t i = 0; i < n; i++) {
    PyObject *v = PyFloat_FromDouble(x[i]);
    if (!v) {
      PyErr_Print();
      Py_DECREF(list);
      return 1.0;
    }
    PyList_SET_ITEM(list, (Py_ssize_t)i, v); /* steals ref */
  }

  PyObject *args = PyTuple_New(1);
  PyTuple_SET_ITEM(args, 0, list); /* steals ref */

  PyObject *ret = PyObject_CallObject(g_py_pred_fn, args);
  Py_DECREF(args);

  if (!ret) {
    PyErr_Print();
    return 1.0;
  }

  double p = PyFloat_AsDouble(ret);
  Py_DECREF(ret);

  if (PyErr_Occurred()) {
    PyErr_Print();
    return 1.0;
  }
  return p;
}

static void ml_joblib_shutdown(void) {
  if (!g_py_inited)
    return;

  Py_XDECREF(g_py_pred_fn);
  Py_XDECREF(g_py_init_fn);
  Py_XDECREF(g_py_mod);

  Py_Finalize();

  g_py_pred_fn = g_py_init_fn = g_py_mod = NULL;
  g_py_inited = 0;
}

/* ---------- tiny FNV-1a 32-bit ------------------------------------ */
static uint32_t fnv1a_32(const char *s) {
  uint32_t h = 0x811c9dc5u;
  while (*s) {
    h ^= (uint8_t)(*s++);
    h *= 0x01000193u;
  }
  return h;
}

/* ---------- UDP Bloom helpers ------------------------------------- */
static inline void udp_bloom_clear(void) { memset(udp_bloom, 0, sizeof udp_bloom); }

static inline void bloom_set_bit(uint32_t bit) { udp_bloom[bit >> 3] |= (uint8_t)(1u << (bit & 7u)); }

static inline int bloom_get_bit(uint32_t bit) { return (udp_bloom[bit >> 3] >> (bit & 7u)) & 1u; }

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
  int fin_cli_done, fin_srv_done;

  struct timeval ts[FLOW_CAP];
  int32_t len[FLOW_CAP]; /* sign encodes direction, magnitude is ip_len */
  int count;

  /* --- timing-wheel bookkeeping (UDP-only) */
  int tw_next;
  int tw_prev;
  int tw_slot;
} flow_entry_t;

static inline int idx_of(flow_entry_t *base, flow_entry_t *e) { return (int)(e - base); }

/*
 * UDP Bloom query:
 * Returns 1 if "probably seen", 0 if "definitely not seen".
 * If add_if_new=1, inserts into bloom when definitely-not-seen.
 */
static inline int udp_bloom_probably_seen_and_maybe_add(const flow_key_t *k, int add_if_new) {
  uint32_t h1 = 2166136261u;
  h1 ^= (uint32_t)k->ip1;
  h1 *= 16777619u;
  h1 ^= (uint32_t)k->ip2;
  h1 *= 16777619u;
  h1 ^= (uint32_t)k->port1;
  h1 *= 16777619u;
  h1 ^= (uint32_t)k->port2;
  h1 *= 16777619u;
  h1 ^= (uint32_t)k->proto;
  h1 *= 16777619u;

  uint32_t h2 = mix32(h1 ^ 0x9e3779b9u);
  if (h2 == 0)
    h2 = 0x27d4eb2du;

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

/* ================================================================= */
/*                     Tables: split by protocol                      */
/* ================================================================= */

/* TCP-only tables */
static flow_entry_t table_tcp[TABLE_SIZE] = {0};
static flow_entry_t aux_tcp[TCP_AUX_SIZE] = {0};

/* UDP-only tables */
static flow_entry_t table_udp[TABLE_SIZE] = {0};
static flow_entry_t aux_udp[UDP_AUX_SIZE] = {0};

/* ================================================================= */
/*                           Timing-wheel (UDP-only)                  */
/* ================================================================= */

static int tw_head_udp_main[TW_SLOTS];
static int tw_head_udp_aux[TW_SLOTS];

static time_t tw_now_sec = 0;
static int tw_now_slot = 0;
static int tw_initialised = 0;
static time_t last_pcap_sec = 0;

/* ---------- stats ------------------------------------------------- */
static uint64_t st_flows_inserted = 0;
static uint64_t st_flows_matched = 0;
static uint64_t st_packets_tracked = 0;

static uint64_t st_aux_inserted = 0;
static uint64_t st_aux_matched = 0;
static uint64_t st_aux_third_dropped = 0;

static uint64_t st_duels = 0;
static uint64_t st_swaps = 0;
static uint64_t st_main_wins = 0;
static uint64_t st_aux_wins = 0;

static uint64_t st_udp_bloom_refused = 0;

/* collision-style stats (like your other code) */
static uint64_t st_collisions = 0;      /* eligible duel/collision events (both sides have FIRST_N) */
static uint64_t st_battles = 0;         /* same as collisions here */
static uint64_t st_challenger_wins = 0; /* aux wins */
static uint64_t st_incumbent_wins = 0;  /* main wins */

static volatile sig_atomic_t g_sigquit_dump_full = 0;
static volatile sig_atomic_t g_in_tw = 0;
static volatile sig_atomic_t g_tw_now_arg = 0;

static uint64_t st_predict_calls = 0;
static uint64_t st_keep_calls = 0;

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

__attribute__((unused)) static void dump_active_flows(time_t now_sec);

/* ================================================================= */
/*   Ground-truth per-flow packet counts + per-flow collision stats   */
/*   + timing: first_ts_us, hit30_ts_us, last_ts_us                   */
/* ================================================================= */
#define GT_SIZE (1u << 22)

typedef struct {
  int in_use;
  flow_key_t key;
  uint32_t pkt_count;
  uint32_t collisions;
  uint32_t wins;
  uint32_t losses;

  uint64_t first_ts_us;
  uint64_t hit30_ts_us;
  uint64_t last_ts_us;
} gt_entry_t;

static gt_entry_t gt_tab[GT_SIZE];

#if (GT_SIZE & (GT_SIZE - 1)) != 0
#error "GT_SIZE must be a power of two"
#endif

static inline uint64_t tv_to_us(const struct timeval *tv) {
  return (uint64_t)tv->tv_sec * 1000000ull + (uint64_t)tv->tv_usec;
}

static inline uint32_t hash_flow_key32(const flow_key_t *k) {
  uint32_t h = 2166136261u;
  h ^= (uint32_t)k->ip1;
  h *= 16777619u;
  h ^= (uint32_t)k->ip2;
  h *= 16777619u;
  h ^= (uint32_t)k->port1;
  h *= 16777619u;
  h ^= (uint32_t)k->port2;
  h *= 16777619u;
  h ^= (uint32_t)k->proto;
  h *= 16777619u;
  return h;
}

static inline int compare_key(const flow_key_t *a, const flow_key_t *b) {
  return !(a->ip1 == b->ip1 && a->ip2 == b->ip2 && a->port1 == b->port1 && a->port2 == b->port2 &&
           a->proto == b->proto);
}

static gt_entry_t *gt_get_or_insert(const flow_key_t *k) {
  uint32_t mask = (uint32_t)(GT_SIZE - 1u);
  uint32_t i = hash_flow_key32(k) & mask;

  for (uint32_t step = 0; step < GT_SIZE; step++) {
    gt_entry_t *e = &gt_tab[i];
    if (!e->in_use) {
      e->in_use = 1;
      e->key = *k;
      e->pkt_count = 0;
      e->collisions = 0;
      e->wins = 0;
      e->losses = 0;
      e->first_ts_us = 0;
      e->hit30_ts_us = 0;
      e->last_ts_us = 0;
      return e;
    }
    if (!compare_key(&e->key, k))
      return e;
    i = (i + 1u) & mask;
  }
  return NULL;
}

/* Ground-truth per-packet update (counts ALL packets regardless of gating). */
static inline void gt_count_packet_tv(const flow_key_t *k, const struct timeval *tv) {
  gt_entry_t *e = gt_get_or_insert(k);
  if (!e)
    return;

  uint64_t t = tv_to_us(tv);
  if (e->first_ts_us == 0)
    e->first_ts_us = t;

  e->pkt_count++;

  if (e->pkt_count == 30 && e->hit30_ts_us == 0)
    e->hit30_ts_us = t;

  e->last_ts_us = t;
}

static inline uint32_t gt_get_pkt_count(const flow_key_t *k) {
  uint32_t mask = (uint32_t)(GT_SIZE - 1u);
  uint32_t i = hash_flow_key32(k) & mask;

  for (uint32_t step = 0; step < GT_SIZE; step++) {
    gt_entry_t *e = &gt_tab[i];
    if (!e->in_use)
      return 0;
    if (!compare_key(&e->key, k))
      return e->pkt_count;
    i = (i + 1u) & mask;
  }
  return 0;
}

static inline void gt_note_collision(const flow_key_t *winner, const flow_key_t *loser) {
  gt_entry_t *w = gt_get_or_insert(winner);
  gt_entry_t *l = gt_get_or_insert(loser);
  if (w) {
    w->collisions++;
    w->wins++;
  }
  if (l) {
    l->collisions++;
    l->losses++;
  }
}

/* ================================================================= */
/*                    Collision event logging (.bin)                  */
/* ================================================================= */
typedef struct {
  flow_key_t winner;
  flow_key_t loser;
  uint8_t winner_was_incumbent; /* 1 if winner was main at duel time */
  uint64_t ts_us;
} collision_rec_t;

static FILE *g_colbin = NULL;

static inline void ip_to_str(uint32_t ip, char out[INET_ADDRSTRLEN]) {
  inet_ntop(AF_INET, &ip, out, INET_ADDRSTRLEN);
}

static inline void log_collision_event(const struct timeval *tv, const flow_key_t *winner, const flow_key_t *loser,
                                       int winner_was_incumbent) {
  if (!g_colbin)
    return;

  collision_rec_t r;
  r.winner = *winner;
  r.loser = *loser;
  r.winner_was_incumbent = (uint8_t)(winner_was_incumbent ? 1 : 0);
  r.ts_us = tv_to_us(tv);

  (void)fwrite(&r, sizeof(r), 1, g_colbin);
  gt_note_collision(winner, loser);
}

static void write_collisions_csv_from_bin(const char *bin_path, const char *csv_path) {
  FILE *in = fopen(bin_path, "rb");
  if (!in) {
    perror("fopen collisions.bin");
    return;
  }

  FILE *out = fopen(csv_path, "w");
  if (!out) {
    perror("fopen collisions.csv");
    fclose(in);
    return;
  }

  fprintf(out,
          "ts_us,"
          "winner_ip1,winner_port1,winner_ip2,winner_port2,winner_proto,"
          "loser_ip1,loser_port1,loser_ip2,loser_port2,loser_proto,"
          "winner_was_incumbent,"
          "winner_pkts,loser_pkts,"
          "winner_ge40,loser_ge40\n");

  collision_rec_t r;
  while (fread(&r, sizeof(r), 1, in) == 1) {
    char wip1[INET_ADDRSTRLEN], wip2[INET_ADDRSTRLEN];
    char lip1[INET_ADDRSTRLEN], lip2[INET_ADDRSTRLEN];
    ip_to_str(r.winner.ip1, wip1);
    ip_to_str(r.winner.ip2, wip2);
    ip_to_str(r.loser.ip1, lip1);
    ip_to_str(r.loser.ip2, lip2);

    uint32_t wp = gt_get_pkt_count(&r.winner);
    uint32_t lp = gt_get_pkt_count(&r.loser);

    int w_ge = (wp >= FLOW_CAP);
    int l_ge = (lp >= FLOW_CAP);

    fprintf(out,
            "%" PRIu64 ","
            "%s,%u,%s,%u,%s,"
            "%s,%u,%s,%u,%s,"
            "%u,"
            "%u,%u,"
            "%d,%d\n",
            r.ts_us, wip1, (unsigned)r.winner.port1, wip2, (unsigned)r.winner.port2,
            (r.winner.proto == IPPROTO_UDP ? "UDP" : "TCP"), lip1, (unsigned)r.loser.port1, lip2,
            (unsigned)r.loser.port2, (r.loser.proto == IPPROTO_UDP ? "UDP" : "TCP"),
            (unsigned)r.winner_was_incumbent, (unsigned)wp, (unsigned)lp, w_ge, l_ge);
  }

  fclose(out);
  fclose(in);
}

static void write_flow_collision_summary_csv(const char *csv_path) {
  FILE *out = fopen(csv_path, "w");
  if (!out) {
    perror("fopen flow_collision_summary.csv");
    return;
  }

  fprintf(out,
          "ip1,port1,ip2,port2,proto,"
          "pkts,ge40,collisions,wins,losses,"
          "first_ts_us,hit30_ts_us,last_ts_us,"
          "dur_to_30_us,dur_30_to_last_us,dur_total_us\n");

  for (uint32_t i = 0; i < GT_SIZE; i++) {
    gt_entry_t *e = &gt_tab[i];
    if (!e->in_use)
      continue;

    char ip1[INET_ADDRSTRLEN], ip2[INET_ADDRSTRLEN];
    ip_to_str(e->key.ip1, ip1);
    ip_to_str(e->key.ip2, ip2);

    uint64_t dur_to_30 = 0;
    if (e->hit30_ts_us != 0 && e->first_ts_us != 0 && e->hit30_ts_us >= e->first_ts_us)
      dur_to_30 = e->hit30_ts_us - e->first_ts_us;

    uint64_t dur_30_to_last = 0;
    if (e->hit30_ts_us != 0 && e->last_ts_us != 0 && e->last_ts_us >= e->hit30_ts_us)
      dur_30_to_last = e->last_ts_us - e->hit30_ts_us;

    uint64_t dur_total = 0;
    if (e->last_ts_us != 0 && e->first_ts_us != 0 && e->last_ts_us >= e->first_ts_us)
      dur_total = e->last_ts_us - e->first_ts_us;

    fprintf(out,
            "%s,%u,%s,%u,%s,"
            "%u,%d,%u,%u,%u,"
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
            ip1, (unsigned)e->key.port1, ip2, (unsigned)e->key.port2, (e->key.proto == IPPROTO_UDP ? "UDP" : "TCP"),
            (unsigned)e->pkt_count, (e->pkt_count >= FLOW_CAP) ? 1 : 0, (unsigned)e->collisions, (unsigned)e->wins,
            (unsigned)e->losses, e->first_ts_us, e->hit30_ts_us, e->last_ts_us, dur_to_30, dur_30_to_last, dur_total);
  }

  fclose(out);
}

/* ================================================================= */
/*                           Timing-wheel helpers                     */
/* ================================================================= */

static void tw_init(time_t start_sec) {
  for (int i = 0; i < TW_SLOTS; ++i) {
    tw_head_udp_main[i] = -1;
    tw_head_udp_aux[i] = -1;
  }
  tw_now_sec = start_sec;
  tw_now_slot = (int)(start_sec % TW_SLOTS);
  tw_initialised = 1;
}

static void tw_remove_generic(flow_entry_t *base, int *tw_head, int idx) {
  flow_entry_t *e = &base[idx];
  if (e->tw_slot < 0)
    return;

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
  if (f->count <= 0)
    return json_object();

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
static flow_key_t make_key(uint32_t s_ip, uint32_t d_ip, uint16_t s_pt, uint16_t d_pt, uint8_t proto) {
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

static inline int coinflip(void) { return rand() & 1; }

static inline double tv_to_sec(const struct timeval *tv) { return (double)tv->tv_sec + (double)tv->tv_usec / 1e6; }

static inline double dabs(double x) { return x < 0 ? -x : x; }

/* ================================================================= */
/*                         CSV logging                                */
/* ================================================================= */
static void write_to_csv(flow_entry_t *e) {
  if (e->count != FLOW_CAP)
    return;

  char ip_small[INET_ADDRSTRLEN], ip_large[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &e->key.ip1, ip_small, sizeof(ip_small));
  inet_ntop(AF_INET, &e->key.ip2, ip_large, sizeof(ip_large));

  char input_field[256];
  snprintf(input_field, sizeof(input_field), "%s%d%s%d%s", ip_small, e->key.port1, ip_large, e->key.port2,
           e->is_udp ? "UDP" : "TCP");

  char feature_vector[4096];
  size_t w = 0;
  w += (size_t)snprintf(feature_vector + w, sizeof(feature_vector) - w, "[");

  double ts_0 = e->ts[0].tv_sec + e->ts[0].tv_usec / 1e6;
  for (int i = 0; i < e->count; ++i) {
    double ts = e->ts[i].tv_sec + e->ts[i].tv_usec / 1e6;
    double offset = ts - ts_0;
    if (e->len[i] < 0)
      offset *= -1;

    w += (size_t)snprintf(feature_vector + w, sizeof(feature_vector) - w, "(%.6f, %.1f)%s", offset, (double)e->len[i],
                          (i < e->count - 1) ? ", " : "");
    if (w >= sizeof(feature_vector))
      break;
  }

  if (w < sizeof(feature_vector))
    (void)snprintf(feature_vector + w, sizeof(feature_vector) - w, "]");

  const char *fname =
      e->is_udp ? "flow_output_timing_wheel_with_joblib_udp.csv" : "flow_output_timing_wheel_with_joblib_tcp.csv";

  FILE *f = fopen(fname, "a");
  if (!f) {
    perror("fopen");
    exit(1);
  }
  fprintf(f, "%s,\"%s\"\n", input_field, feature_vector);
  fclose(f);
}

/* ================================================================= */
/*                     flow finalisation & output                     */
/* ================================================================= */

static void dump_and_clear_main(flow_entry_t *e) {
  if (e->is_udp) {
    if (e >= &table_udp[0] && e < &table_udp[TABLE_SIZE]) {
      int idx = idx_of(table_udp, e);
      tw_remove_generic(table_udp, tw_head_udp_main, idx);
    }
  }

  if (WRITE_TO_CSV)
    write_to_csv(e);

  if (SHOW_OUTPUT) {
    char ca[INET_ADDRSTRLEN], sa[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->cli_ip, ca, sizeof ca);
    inet_ntop(AF_INET, &e->srv_ip, sa, sizeof sa);
    fprintf(stderr, "Flow %s:%u ↔ %s:%u %s pkts:%d\n", ca, e->cli_port, sa, e->srv_port, e->is_udp ? "UDP" : "TCP",
            e->count);
  }

  enqueue_flow(e);

  memset(e, 0, sizeof *e);
  e->tw_slot = e->tw_next = e->tw_prev = -1;
}

static void drop_and_clear_aux(flow_entry_t *e) {
  if (e->is_udp) {
    if (e >= &aux_udp[0] && e < &aux_udp[UDP_AUX_SIZE]) {
      int idx = idx_of(aux_udp, e);
      tw_remove_generic(aux_udp, tw_head_udp_aux, idx);
    }
  }
  memset(e, 0, sizeof *e);
  e->tw_slot = e->tw_next = e->tw_prev = -1;
}

/* ================================================================= */
/*                 timing-wheel advance logic (UDP-only)              */
/* ================================================================= */

static void expire_slot_lists(int slot) {
  int idx = tw_head_udp_main[slot];
  tw_head_udp_main[slot] = -1;
  while (idx != -1) {
    int nxt = table_udp[idx].tw_next;
    table_udp[idx].tw_slot = table_udp[idx].tw_next = -1;
    dump_and_clear_main(&table_udp[idx]);
    idx = nxt;
  }

  idx = tw_head_udp_aux[slot];
  tw_head_udp_aux[slot] = -1;
  while (idx != -1) {
    int nxt = aux_udp[idx].tw_next;
    aux_udp[idx].tw_slot = aux_udp[idx].tw_next = -1;
    drop_and_clear_aux(&aux_udp[idx]);
    idx = nxt;
  }
}

static void tw_advance(time_t now_sec) {
  g_in_tw = 1;
  g_tw_now_arg = (sig_atomic_t)now_sec;
  if (!tw_initialised)
    tw_init(now_sec);

  if (now_sec <= tw_now_sec) {
    g_in_tw = 0;
    return;
  }

  time_t delta = now_sec - tw_now_sec;
  if (delta > 10) {
    fprintf(stderr, "tw_advance: tw_now_sec=%ld now_sec=%ld delta=%ld\n", (long)tw_now_sec, (long)now_sec,
            (long)delta);
  }

  if (delta >= TW_SLOTS) {
    for (int s = 0; s < TW_SLOTS; ++s) {
      expire_slot_lists(s);
    }
    tw_now_sec = now_sec;
    tw_now_slot = (int)(now_sec % TW_SLOTS);
    g_in_tw = 0;
    return;
  }

  while (tw_now_sec < now_sec) {
    tw_now_sec++;
    tw_now_slot = (tw_now_slot + 1) & (TW_SLOTS - 1);
    expire_slot_lists(tw_now_slot);
  }

  g_in_tw = 0;
}

/* ================================================================= */
/*                 ML feature extraction (matches training)           */
/* ================================================================= */

static void stats_1d(const double *a, int n, double *out_mean, double *out_std, double *out_min, double *out_max,
                     double *out_sum) {
  double sum = 0.0;
  double mn = a[0], mx = a[0];
  for (int i = 0; i < n; i++) {
    double v = a[i];
    sum += v;
    if (v < mn)
      mn = v;
    if (v > mx)
      mx = v;
  }
  double mean = sum / (double)n;

  double var = 0.0;
  for (int i = 0; i < n; i++) {
    double d = a[i] - mean;
    var += d * d;
  }
  var /= (double)n;
  double std = (var > 0.0) ? sqrt(var) : 0.0;

  *out_mean = mean;
  *out_std = std;
  *out_min = mn;
  *out_max = mx;
  *out_sum = sum;
}

/* Order matches your Python training script:
 *  s1..s8, dt2..dt8, mean_size,std_size,min_size,max_size,sum_size,
 *  mean_dt,std_dt,min_dt,max_dt, span_8, pps_8, bps_8
 */
static int build_feature_entries_first8_doubles(const flow_entry_t *e, double *x, int nfeat) {
  if (e->count < FIRST_N)
    return 0;
  if (nfeat != NFEAT)
    return 0;

  double t[8], s[8];
  for (int i = 0; i < 8; i++) {
    t[i] = tv_to_sec(&e->ts[i]);
    s[i] = dabs((double)e->len[i]);
  }

  double dt[7];
  for (int i = 0; i < 7; i++)
    dt[i] = t[i + 1] - t[i];

  double span = t[7] - t[0];
  const double eps = 1e-9;

  double mean_size, std_size, min_size, max_size, sum_size;
  stats_1d(s, 8, &mean_size, &std_size, &min_size, &max_size, &sum_size);

  double mean_dt, std_dt, min_dt, max_dt, sum_dt;
  (void)sum_dt;
  stats_1d(dt, 7, &mean_dt, &std_dt, &min_dt, &max_dt, &sum_dt);

  double pps_8 = 8.0 / (span + eps);
  double bps_8 = sum_size / (span + eps);

  int k = 0;
  for (int i = 0; i < 8; i++)
    x[k++] = s[i];
  for (int i = 0; i < 7; i++)
    x[k++] = dt[i];

  x[k++] = mean_size;
  x[k++] = std_size;
  x[k++] = min_size;
  x[k++] = max_size;
  x[k++] = sum_size;

  x[k++] = mean_dt;
  x[k++] = std_dt;
  x[k++] = min_dt;
  x[k++] = max_dt;
  x[k++] = span;

  x[k++] = pps_8;
  x[k++] = bps_8;

  return (k == nfeat);
}

static inline double score_reach40(const flow_entry_t *e) {
  st_predict_calls++;

  double x[NFEAT];
  if (!build_feature_entries_first8_doubles(e, x, NFEAT))
    return 1.0;

  return ml_joblib_predict_proba1(x, (size_t)NFEAT);
}

static inline int keep_yesno(const flow_entry_t *e) {
  st_keep_calls++;
  double p = score_reach40(e);
  return (p >= EVICT_THRESHOLD);
}

/* ================================================================= */
/*                 Contention resolution (generic)                    */
/* ================================================================= */

static void reschedule_udp_if_needed(flow_entry_t *base, int *tw_head, flow_entry_t *e, time_t now_sec) {
  if (!e->in_use)
    return;
  if (!e->is_udp)
    return;
  int idx = idx_of(base, e);
  tw_insert_generic(base, tw_head, idx, now_sec + UDP_IDLE_SEC);
}

/* swap uses two indices (main vs aux). */
static void swap_main_aux_bucket_generic(flow_entry_t *main_base, flow_entry_t *aux_base, int *tw_head_main,
                                        int *tw_head_aux, uint32_t p_main, uint32_t p_aux, time_t now_sec) {
  flow_entry_t tmp = main_base[p_main];
  main_base[p_main] = aux_base[p_aux];
  aux_base[p_aux] = tmp;

  /* Only UDP tables participate in the timing wheel. */
  if (tw_head_main && tw_head_aux) {
    main_base[p_main].tw_slot = main_base[p_main].tw_next = main_base[p_main].tw_prev = -1;
    aux_base[p_aux].tw_slot = aux_base[p_aux].tw_next = aux_base[p_aux].tw_prev = -1;

    reschedule_udp_if_needed(main_base, tw_head_main, &main_base[p_main], now_sec);
    reschedule_udp_if_needed(aux_base, tw_head_aux, &aux_base[p_aux], now_sec);
  }

  st_swaps++;
}

/* UPDATED signature: takes tv for logging ts_us */
static void resolve_duel_bucket_generic(flow_entry_t *main_base, flow_entry_t *aux_base, int *tw_head_main,
                                       int *tw_head_aux, uint32_t p_main, uint32_t p_aux, const struct timeval *tv) {
  time_t now_sec = tv->tv_sec;

  flow_entry_t *m = &main_base[p_main];
  flow_entry_t *a = &aux_base[p_aux];
  if (!m->in_use || !a->in_use)
    return;

  /* Safety: don't "duel" if they are actually the same key. */
  if (!compare_key(&m->key, &a->key))
    return;

  /* If aux has enough to be scored but main doesn't, prioritize aux */
  if (a->count >= FIRST_N && m->count < FIRST_N) {
    swap_main_aux_bucket_generic(main_base, aux_base, tw_head_main, tw_head_aux, p_main, p_aux, now_sec);
    return;
  }

  if (m->count >= FIRST_N && a->count >= FIRST_N) {
    st_duels++;
    st_collisions++;
    st_battles++;

    /* snapshot keys for logging */
    flow_key_t mkey = m->key;
    flow_key_t akey = a->key;

    int m_keep = keep_yesno(m);
    int a_keep = keep_yesno(a);

    int keep_main;
    if (m_keep && !a_keep)
      keep_main = 1;
    else if (!m_keep && a_keep)
      keep_main = 0;
    else
      keep_main = coinflip();

    if (!keep_main) {
      /* aux wins */
      st_aux_wins++;
      st_challenger_wins++;

      log_collision_event(tv, &akey, &mkey, 0);

      swap_main_aux_bucket_generic(main_base, aux_base, tw_head_main, tw_head_aux, p_main, p_aux, now_sec);

    } else {
      /* main wins */
      st_main_wins++;
      st_incumbent_wins++;

      log_collision_event(tv, &mkey, &akey, 1);
    }

    /* drop loser (now in aux slot) */
    drop_and_clear_aux(&aux_base[p_aux]);
  }
}

/* ================================================================= */
/*                 packet tracking (called per packet)                */
/* ================================================================= */

static void init_new_entry(flow_entry_t *e, flow_key_t key, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport,
                           uint8_t proto) {
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

static void track_packet(const struct timeval *tv, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport,
                         uint8_t proto, int tcp_syn, int tcp_fin, uint16_t ip_len) {
  (void)tcp_fin;

  if (g_sigquit_dump_full) {
    g_sigquit_dump_full = 0;

    int tcp_main = 0, tcp_aux = 0;
    int udp_main = 0, udp_aux = 0;

    for (int i = 0; i < TABLE_SIZE; i++) {
      if (table_tcp[i].in_use)
        tcp_main++;
      if (table_udp[i].in_use)
        udp_main++;
    }
    for (int i = 0; i < TCP_AUX_SIZE; i++) {
      if (aux_tcp[i].in_use)
        tcp_aux++;
    }
    for (int i = 0; i < UDP_AUX_SIZE; i++) {
      if (aux_udp[i].in_use)
        udp_aux++;
    }

    fprintf(stderr, "ACTIVE: tcp_main=%d tcp_aux=%d udp_main=%d udp_aux=%d (tw_now=%ld slot=%d)\n", tcp_main, tcp_aux,
            udp_main, udp_aux, (long)tw_now_sec, tw_now_slot);
  }

  tw_advance(tv->tv_sec);

  flow_key_t key = make_key(sip, dip, sport, dport, proto);

  /* Ground truth always counts packets and updates timestamps */
  gt_count_packet_tv(&key, tv);

  char kbuf[64];
  snprintf(kbuf, sizeof kbuf, "%08x%04x%08x%04x%02x", key.ip1, key.port1, key.ip2, key.port2, key.proto);
  uint32_t h = fnv1a_32(kbuf);

  /* Correct protocol-specific indexing */
  uint32_t p_main = h & (TABLE_SIZE - 1);
  uint32_t p_aux = (proto == IPPROTO_UDP) ? (h & (UDP_AUX_SIZE - 1)) : (h & (TCP_AUX_SIZE - 1));

  flow_entry_t *main_base;
  flow_entry_t *aux_base;
  int *tw_head_main = NULL;
  int *tw_head_aux = NULL;

  if (proto == IPPROTO_UDP) {
    main_base = table_udp;
    aux_base = aux_udp;
    tw_head_main = tw_head_udp_main;
    tw_head_aux = tw_head_udp_aux;
  } else {
    main_base = table_tcp;
    aux_base = aux_tcp;
  }

  flow_entry_t *m = &main_base[p_main];
  flow_entry_t *a = &aux_base[p_aux];

  flow_entry_t *e = NULL;
  int is_new = 0;
  int is_aux = 0;

  if (!m->in_use) {
    e = m;
    is_new = 1;
    is_aux = 0;
  } else if (!compare_key(&m->key, &key)) {
    e = m;
    is_new = 0;
    is_aux = 0;
  } else {
    /* collision with main */
    if (!a->in_use) {
      e = a;
      is_new = 1;
      is_aux = 1;
    } else if (!compare_key(&a->key, &key)) {
      e = a;
      is_new = 0;
      is_aux = 1;
    } else {
      st_aux_third_dropped++;
      return;
    }
  }

  if (is_new) {
    if (proto == IPPROTO_TCP && !tcp_syn)
      return;

    if (proto == IPPROTO_UDP) {
      int seen = udp_bloom_probably_seen_and_maybe_add(&key, 1);
      if (seen) {
        st_udp_bloom_refused++;
        return;
      }
    }

    init_new_entry(e, key, sip, dip, sport, dport, proto);
    if (is_aux)
      st_aux_inserted++;
    else
      st_flows_inserted++;
  } else {
    if (is_aux)
      st_aux_matched++;
    else
      st_flows_matched++;
  }

  if (e->count < FLOW_CAP) {
    int from_cli = (sip == e->cli_ip && sport == e->cli_port);
    e->ts[e->count] = *tv;
    e->len[e->count] = (from_cli ? +1 : -1) * (int32_t)ip_len;
    e->count++;
    st_packets_tracked++;
  }

  /* UDP: reschedule using correct index for whichever table the entry lives in */
  if (e->is_udp) {
    if (is_aux)
      tw_insert_generic(aux_base, tw_head_aux, (int)p_aux, tv->tv_sec + UDP_IDLE_SEC);
    else
      tw_insert_generic(main_base, tw_head_main, (int)p_main, tv->tv_sec + UDP_IDLE_SEC);
  }

  if (!is_aux && e->count == FLOW_CAP) {
    dump_and_clear_main(e);
    return;
  }

  /* Duel only if both occupied and not same key */
  if (m->in_use && a->in_use && compare_key(&m->key, &a->key)) {
    resolve_duel_bucket_generic(main_base, aux_base, tw_head_main, tw_head_aux, p_main, p_aux, tv);
  }
}

/* ================================================================= */
/*                parse Ethernet/IP/TCP/UDP & call tracker            */
/* ================================================================= */
static int parse_and_track(const struct pcap_pkthdr *h, const u_char *pkt) {
  const struct ether_header *eth = (const struct ether_header *)pkt;
  if (ntohs(eth->ether_type) != ETHERTYPE_IP)
    return 0;

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
                   "in_tw=%d tw_arg=%d tw_now_sec=%ld slot=%d\n"
                   "... duels=%" PRIu64 " keep_calls=%" PRIu64 " predict_calls=%" PRIu64 "\n"
                   "ZMQ fill=%zu exiting=%d\n",
                   (int)g_in_tw, (int)g_tw_now_arg, (long)tw_now_sec, tw_now_slot, st_duels, st_keep_calls,
                   st_predict_calls, fill, exiting);

  if (n > 0) {
    ssize_t wr = write(STDERR_FILENO, buf, (size_t)n);
    (void)wr;
  }
}

/* Optional debug dump (currently unused) */
static void dump_active_flows(time_t now_sec) {
  int tcp_main = 0, tcp_aux = 0;
  int udp_main = 0, udp_aux = 0;

  fprintf(stderr, "\n=== DUMP ACTIVE FLOWS (now=%ld, tw_now=%ld slot=%d) ===\n", (long)now_sec, (long)tw_now_sec,
          tw_now_slot);

  for (int i = 0; i < TABLE_SIZE; ++i) {
    if (table_tcp[i].in_use)
      tcp_main++;
    if (table_udp[i].in_use)
      udp_main++;
  }
  for (int i = 0; i < TCP_AUX_SIZE; ++i) {
    if (aux_tcp[i].in_use)
      tcp_aux++;
  }
  for (int i = 0; i < UDP_AUX_SIZE; ++i) {
    if (aux_udp[i].in_use)
      udp_aux++;
  }

  fprintf(stderr, "Totals: tcp_main=%d tcp_aux=%d udp_main=%d udp_aux=%d\n", tcp_main, tcp_aux, udp_main, udp_aux);
  fprintf(stderr, "ZMQ buffer: fill=%zu head=%zu tail=%zu exiting=%d\n", fill, head, tail, exiting);
  fprintf(stderr, "UDP bloom refused new entries: %" PRIu64 "\n", st_udp_bloom_refused);
  fprintf(stderr, "=== END DUMP ===\n\n");
}

/* ================================================================= */
/*                                main                               */
/* ================================================================= */
int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s file.pcap model.joblib\n", argv[0]);
    return 1;
  }
  signal(SIGQUIT, on_sigquit);

  /* init Python + load model */
  if (!ml_joblib_init(argv[2])) {
    fprintf(stderr, "ERROR: failed to init joblib model: %s\n", argv[2]);
    return 1;
  }

  srand((unsigned)time(NULL));
  udp_bloom_clear();
  memset(gt_tab, 0, sizeof(gt_tab));

  /* open collision bin log */
  g_colbin = fopen("joblib_two_tables_collisions.bin", "wb");
  if (!g_colbin) {
    perror("fopen joblib_two_tables_collisions.bin");
    ml_joblib_shutdown();
    return 1;
  }

  char err[PCAP_ERRBUF_SIZE];
  fprintf(stderr, "main: starting\n");
  pcap_t *pc = pcap_open_offline(argv[1], err);
  if (!pc) {
    fprintf(stderr, "pcap_open: %s\n", err);
    fclose(g_colbin);
    g_colbin = NULL;
    ml_joblib_shutdown();
    return 1;
  }
  fprintf(stderr, "main: pcap opened\n");

  if (pthread_create(&zmq_thread, NULL, sender_thread, NULL) != 0) {
    perror("pthread_create");
    pcap_close(pc);
    fclose(g_colbin);
    g_colbin = NULL;
    ml_joblib_shutdown();
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
        fprintf(stderr, "pcap_next_ex: rc==0 zeros=%" PRIu64 " iters=%" PRIu64 "\n", zeros, iters);
      }
      continue;
    }

    pkts++;
    if ((pkts % 10000ULL) == 0) {
      fprintf(stderr, "pcap: pkts=%" PRIu64 " iters=%" PRIu64 " last_ts=%ld\n", pkts, iters, (long)h->ts.tv_sec);
    }

    parse_and_track(h, pkt);
  }

  if (rc == -1)
    fprintf(stderr, "pcap error: %s\n", pcap_geterr(pc));
  fprintf(stderr, "main: pcap loop done rc=%d\n", rc);

  if (last_pcap_sec != 0) {
    tw_advance(last_pcap_sec + UDP_IDLE_SEC + TW_SLOTS);
  }

  for (int i = 0; i < TABLE_SIZE; ++i) {
    if (table_tcp[i].in_use)
      dump_and_clear_main(&table_tcp[i]);
    if (table_udp[i].in_use)
      dump_and_clear_main(&table_udp[i]);
  }

  for (int i = 0; i < TCP_AUX_SIZE; ++i) {
    if (aux_tcp[i].in_use)
      drop_and_clear_aux(&aux_tcp[i]);
  }
  for (int i = 0; i < UDP_AUX_SIZE; ++i) {
    if (aux_udp[i].in_use)
      drop_and_clear_aux(&aux_udp[i]);
  }

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
          " duels=%" PRIu64 " swaps=%" PRIu64 " main_wins=%" PRIu64 " aux_wins=%" PRIu64
          " collisions=%" PRIu64 " battles=%" PRIu64 " challenger_wins=%" PRIu64 " incumbent_wins=%" PRIu64
          " udp_bloom_refused=%" PRIu64 "\n",
          st_flows_inserted, st_flows_matched, st_aux_inserted, st_aux_matched, st_aux_third_dropped, st_packets_tracked,
          st_duels, st_swaps, st_main_wins, st_aux_wins, st_collisions, st_battles, st_challenger_wins,
          st_incumbent_wins, st_udp_bloom_refused);

  /* close collision bin and write CSV outputs */
  if (g_colbin) {
    fclose(g_colbin);
    g_colbin = NULL;
  }

  write_collisions_csv_from_bin("joblib_two_tables_collisions.bin", "joblib_two_tables_collisions.csv");
  write_flow_collision_summary_csv("joblib_two_tables_flow_collision_summary.csv");

  /* shutdown Python */
  ml_joblib_shutdown();

  return 0;
}
