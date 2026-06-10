/*********************************************************************
 *  flowhash_zmq_timing_wheel_random_chance_bloom_seeded.c
 *
 *  UPDATE (your request):
 *   - Different table sizes for TCP vs UDP
 *     TCP table size = TABLE_SIZE_TCP
 *     UDP table size = TABLE_SIZE_UDP = TABLE_SIZE_TCP / 4
 *   - TCP admission no longer uses SYN flags.
 *     TCP now uses its own Bloom filter admission gate, parallel to UDP.
 *
 *  Random Chance version: on an eligible collision, the challenger replaces
 *     the incumbent with a fixed probability, rather than the WRC
 *     count-dependent probability.
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
#define TABLE_SIZE_TCP (4096)       /* must be power of 2 */
#define TABLE_SIZE_UDP (TABLE_SIZE_TCP / 4) /* must be power of 2 */
#define FLOW_CAP 40             /* pkts per flow      */
#define RANDOM_REPLACE_PROB 0.5 /* challenger replacement probability on collision */
#define UDP_IDLE_SEC 30         /* idle timeout UDP   */
#define TW_SLOTS 256            /* must be power of 2 */
#define BUF_MAX 64              /* ring buffer slots  */
#define BATCH_SIZE 16           /* flows per JSON msg */
#define SHOW_OUTPUT 0           /* stderr debug prints */
#define WRITE_TO_CSV 1

/* ZMQ shutdown / blocking behavior */
#define ZMQ_LINGER_MS 0
#define ZMQ_SNDTIMEO_MS 100
#define ZMQ_ENDPOINT "ipc:///tmp/flowpipe"

/* ---------- Bloom filters for admission gates --------------------- */
/* TCP and UDP are kept separate so they do not contaminate each other. */
#define TCP_BLOOM_BITS   (1u << 28)
#define TCP_BLOOM_BYTES  (TCP_BLOOM_BITS / 8u)
#define TCP_BLOOM_K 4
static uint8_t tcp_bloom[TCP_BLOOM_BYTES];

#define UDP_BLOOM_BITS   (1u << 28)
#define UDP_BLOOM_BYTES  (UDP_BLOOM_BITS / 8u)
#define UDP_BLOOM_K 4
static uint8_t udp_bloom[UDP_BLOOM_BYTES];

/* compile-time guards */
#if (TABLE_SIZE_TCP & (TABLE_SIZE_TCP - 1)) != 0
#error "TABLE_SIZE_TCP must be a power of two"
#endif
#if (TABLE_SIZE_UDP & (TABLE_SIZE_UDP - 1)) != 0
#error "TABLE_SIZE_UDP must be a power of two"
#endif
#if (TABLE_SIZE_TCP % 4) != 0
#error "TABLE_SIZE_TCP must be divisible by 4 so TABLE_SIZE_UDP is an integer"
#endif
#if (TW_SLOTS & (TW_SLOTS - 1)) != 0
#error "TW_SLOTS must be a power of two"
#endif
#if (TCP_BLOOM_BITS & (TCP_BLOOM_BITS - 1)) != 0
#error "TCP_BLOOM_BITS must be a power of two"
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
static inline void tcp_bloom_clear(void) { memset(tcp_bloom, 0, sizeof tcp_bloom); }
static inline void udp_bloom_clear(void) { memset(udp_bloom, 0, sizeof udp_bloom); }

static inline void bloom_set_bit(uint8_t *bloom, uint32_t bit) {
  bloom[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
}

static inline int bloom_get_bit(const uint8_t *bloom, uint32_t bit) {
  return (bloom[bit >> 3] >> (bit & 7u)) & 1u;
}

static inline uint32_t mix32(uint32_t x) {
  x ^= x >> 16; x *= 0x7feb352du;
  x ^= x >> 15; x *= 0x846ca68bu;
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
  int32_t len[FLOW_CAP];
  int count;

  uint32_t wins;

  /* timing-wheel bookkeeping (UDP-only) */
  int tw_next, tw_prev, tw_slot;
} flow_entry_t;

static inline int idx_of(flow_entry_t *base, flow_entry_t *e) { return (int)(e - base); }

static inline int compare_key(const flow_key_t *a, const flow_key_t *b) {
  return !(a->ip1 == b->ip1 && a->ip2 == b->ip2 &&
           a->port1 == b->port1 && a->port2 == b->port2 &&
           a->proto == b->proto);
}

/* Returns 1 if "probably seen", 0 if "definitely not seen".
   If add_if_new=1 and definitely-not-seen, also inserts into bloom. */
static inline int bloom_probably_seen_and_maybe_add(uint8_t *bloom,
                                                    uint32_t bloom_bits,
                                                    uint32_t bloom_k,
                                                    const flow_key_t *k,
                                                    int add_if_new)
{
  uint32_t h1 = 2166136261u;
  h1 ^= (uint32_t)k->ip1;   h1 *= 16777619u;
  h1 ^= (uint32_t)k->ip2;   h1 *= 16777619u;
  h1 ^= (uint32_t)k->port1; h1 *= 16777619u;
  h1 ^= (uint32_t)k->port2; h1 *= 16777619u;
  h1 ^= (uint32_t)k->proto; h1 *= 16777619u;

  uint32_t h2 = mix32(h1 ^ 0x9e3779b9u);
  if (h2 == 0) h2 = 0x27d4eb2du;

  uint32_t mask = bloom_bits - 1u;

  for (uint32_t i = 0; i < bloom_k; i++) {
    uint32_t bit = (h1 + i * h2) & mask;
    if (!bloom_get_bit(bloom, bit)) {
      if (add_if_new) {
        for (uint32_t j = 0; j < bloom_k; j++) {
          uint32_t b2 = (h1 + j * h2) & mask;
          bloom_set_bit(bloom, b2);
        }
      }
      return 0;
    }
  }
  return 1;
}

/* ================================================================= */
/*                 Deterministic RNG (xorshift32)                     */
/* ================================================================= */
static uint32_t g_rng_state = 1u;

static inline void rng_seed(uint32_t seed) {
  if (seed == 0) seed = 1u;
  g_rng_state = seed;
}

static inline uint32_t rng32(void) {
  uint32_t x = g_rng_state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  g_rng_state = x;
  return x;
}

/* ================================================================= */
/*                      Random Chance eviction function               */
/* ================================================================= */
static inline int evict_prob_random_chance(const flow_entry_t *e)
{
  (void)e;

  uint32_t r = rng32();
  double u = (double)r / 4294967296.0;
  return u < RANDOM_REPLACE_PROB;
}

/* ================================================================= */
/*                     Tables: split by protocol                      */
/* ================================================================= */
static flow_entry_t table_tcp[TABLE_SIZE_TCP] = {0};
static flow_entry_t table_udp[TABLE_SIZE_UDP] = {0};

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

static uint64_t st_collisions = 0;      /* eligible collision events */
static uint64_t st_battles = 0;         /* same as collisions here */
static uint64_t st_challenger_wins = 0;
static uint64_t st_incumbent_wins  = 0;

static uint64_t st_tcp_bloom_refused = 0;
static uint64_t st_udp_bloom_refused = 0;
static uint64_t st_cap_flushes = 0;

/* ================================================================= */
/*    Ground-truth per-flow packet counts + per-flow collision stats  */
/*    + timing: first_ts_us, hit30_ts_us, last_ts_us                  */
/* ================================================================= */
#define GT_SIZE (1u << 22)

typedef struct {
  int in_use;
  flow_key_t key;
  uint32_t pkt_count;
  uint32_t collisions;
  uint32_t wins;
  uint32_t losses;

  uint64_t first_ts_us;   /* ts of first packet seen */
  uint64_t hit30_ts_us;   /* ts when pkt_count becomes 30 (0 if never) */
  uint64_t last_ts_us;    /* ts of most recent packet seen */
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
  h ^= (uint32_t)k->ip1;   h *= 16777619u;
  h ^= (uint32_t)k->ip2;   h *= 16777619u;
  h ^= (uint32_t)k->port1; h *= 16777619u;
  h ^= (uint32_t)k->port2; h *= 16777619u;
  h ^= (uint32_t)k->proto; h *= 16777619u;
  return h;
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
    if (!compare_key(&e->key, k)) return e;
    i = (i + 1u) & mask;
  }
  return NULL;
}

/* Ground-truth per-packet update (counts ALL packets regardless of gating). */
static inline void gt_count_packet_tv(const flow_key_t *k, const struct timeval *tv) {
  gt_entry_t *e = gt_get_or_insert(k);
  if (!e) return;

  uint64_t t = tv_to_us(tv);

  if (e->first_ts_us == 0) e->first_ts_us = t;

  e->pkt_count++;

  if (e->pkt_count == 30 && e->hit30_ts_us == 0) e->hit30_ts_us = t;

  e->last_ts_us = t;
}

static inline uint32_t gt_get_pkt_count(const flow_key_t *k) {
  uint32_t mask = (uint32_t)(GT_SIZE - 1u);
  uint32_t i = hash_flow_key32(k) & mask;

  for (uint32_t step = 0; step < GT_SIZE; step++) {
    gt_entry_t *e = &gt_tab[i];
    if (!e->in_use) return 0;
    if (!compare_key(&e->key, k)) return e->pkt_count;
    i = (i + 1u) & mask;
  }
  return 0;
}

static inline void gt_note_collision(const flow_key_t *winner, const flow_key_t *loser) {
  gt_entry_t *w = gt_get_or_insert(winner);
  gt_entry_t *l = gt_get_or_insert(loser);
  if (w) { w->collisions++; w->wins++; }
  if (l) { l->collisions++; l->losses++; }
}

/* ================================================================= */
/*                         Collision event logging                    */
/* ================================================================= */
typedef struct {
  flow_key_t winner;
  flow_key_t loser;
  uint8_t winner_was_incumbent;
  uint64_t ts_us;
} collision_rec_t;

static FILE *g_colbin = NULL;

/* ================================================================= */
/* Bucket empty/busy tracking for M/G/1 loss-system analysis          */
/* ================================================================= */
typedef struct {
  int initialized;
  int is_busy;

  uint64_t total_eligible_arrivals;    /* new-flow attempts that map to this bucket */
  uint64_t accepted_on_empty;          /* arrivals that found the bucket empty */
  uint64_t arrivals_while_busy;        /* arrivals that found the bucket occupied */
  uint64_t challenger_wins;            /* Random Chance replacement wins */
  uint64_t incumbent_wins;             /* incumbent keeps bucket */

  uint64_t exports_all;                /* any flow leaving the bucket */
  uint64_t exports_ge_cap;             /* flows leaving with count >= FLOW_CAP */
  uint64_t exports_partial;            /* flows leaving before FLOW_CAP */

  uint64_t busy_periods;
  uint64_t sum_busy_us;
  uint64_t min_busy_us;
  uint64_t max_busy_us;

  uint64_t empty_periods;
  uint64_t sum_empty_us;

  uint64_t busy_start_us;
  uint64_t last_empty_start_us;
} bucket_stat_t;

static bucket_stat_t bucket_tcp[TABLE_SIZE_TCP];
static bucket_stat_t bucket_udp[TABLE_SIZE_UDP];

static FILE *g_bucket_busy_csv = NULL;
static FILE *g_bucket_empty_csv = NULL;

static uint64_t g_first_pcap_ts_us = 0;
static uint64_t g_last_pcap_ts_us = 0;

static inline bucket_stat_t *bucket_stats(uint8_t proto, uint32_t bucket_idx) {
  return (proto == IPPROTO_UDP) ? &bucket_udp[bucket_idx] : &bucket_tcp[bucket_idx];
}

static inline const char *proto_name_u8(uint8_t proto) {
  return (proto == IPPROTO_UDP) ? "UDP" : "TCP";
}

static void bucket_stats_init_all(void) {
  memset(bucket_tcp, 0, sizeof(bucket_tcp));
  memset(bucket_udp, 0, sizeof(bucket_udp));
}

static void open_bucket_period_csvs(void) {
  g_bucket_busy_csv = fopen("rc_bucket_busy_periods.csv", "w");
  if (!g_bucket_busy_csv) { perror("fopen rc_bucket_busy_periods.csv"); exit(1); }

  g_bucket_empty_csv = fopen("rc_bucket_empty_periods.csv", "w");
  if (!g_bucket_empty_csv) { perror("fopen rc_bucket_empty_periods.csv"); exit(1); }

  fprintf(g_bucket_busy_csv,
          "proto,bucket_idx,busy_start_us,busy_end_us,busy_duration_us,reason,flow_count,ge_cap\n");

  fprintf(g_bucket_empty_csv,
          "proto,bucket_idx,empty_start_us,empty_end_us,empty_duration_us,reason\n");
}

static void close_bucket_period_csvs(void) {
  if (g_bucket_busy_csv) { fclose(g_bucket_busy_csv); g_bucket_busy_csv = NULL; }
  if (g_bucket_empty_csv) { fclose(g_bucket_empty_csv); g_bucket_empty_csv = NULL; }
}

static inline void bucket_ensure_initialized(bucket_stat_t *bs) {
  if (!bs->initialized) {
    bs->initialized = 1;
    bs->is_busy = 0;
    bs->last_empty_start_us = g_first_pcap_ts_us ? g_first_pcap_ts_us : g_last_pcap_ts_us;
    bs->min_busy_us = UINT64_MAX;
  }
}

static void bucket_note_arrival(uint8_t proto, uint32_t bucket_idx, int bucket_was_empty) {
  bucket_stat_t *bs = bucket_stats(proto, bucket_idx);
  bucket_ensure_initialized(bs);

  bs->total_eligible_arrivals++;
  if (bucket_was_empty) bs->accepted_on_empty++;
  else bs->arrivals_while_busy++;
}

static void bucket_transition_to_busy(uint8_t proto, uint32_t bucket_idx, uint64_t t_us) {
  bucket_stat_t *bs = bucket_stats(proto, bucket_idx);
  bucket_ensure_initialized(bs);

  if (!bs->is_busy) {
    if (bs->last_empty_start_us != 0 && t_us >= bs->last_empty_start_us) {
      uint64_t dur = t_us - bs->last_empty_start_us;
      bs->empty_periods++;
      bs->sum_empty_us += dur;
      if (g_bucket_empty_csv) {
        fprintf(g_bucket_empty_csv, "%s,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",arrival_to_empty_bucket\n",
                proto_name_u8(proto), (unsigned)bucket_idx,
                bs->last_empty_start_us, t_us, dur);
      }
    }
    bs->is_busy = 1;
    bs->busy_start_us = t_us;
  }
}

static void bucket_transition_to_empty(uint8_t proto, uint32_t bucket_idx,
                                       uint64_t t_us, const char *reason,
                                       int flow_count, int ge_cap) {
  bucket_stat_t *bs = bucket_stats(proto, bucket_idx);
  bucket_ensure_initialized(bs);

  bs->exports_all++;
  if (ge_cap) bs->exports_ge_cap++;
  else bs->exports_partial++;

  if (bs->is_busy) {
    uint64_t dur = (t_us >= bs->busy_start_us) ? (t_us - bs->busy_start_us) : 0;
    bs->busy_periods++;
    bs->sum_busy_us += dur;
    if (dur < bs->min_busy_us) bs->min_busy_us = dur;
    if (dur > bs->max_busy_us) bs->max_busy_us = dur;

    if (g_bucket_busy_csv) {
      fprintf(g_bucket_busy_csv, "%s,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%s,%d,%d\n",
              proto_name_u8(proto), (unsigned)bucket_idx,
              bs->busy_start_us, t_us, dur,
              reason ? reason : "unknown", flow_count, ge_cap);
    }

    bs->is_busy = 0;
    bs->last_empty_start_us = t_us;
  }
}

static void bucket_note_challenger_win(uint8_t proto, uint32_t bucket_idx) {
  bucket_stats(proto, bucket_idx)->challenger_wins++;
}

static void bucket_note_incumbent_win(uint8_t proto, uint32_t bucket_idx) {
  bucket_stats(proto, bucket_idx)->incumbent_wins++;
}

static void bucket_finalize_empty_periods(uint64_t end_us) {
  if (end_us == 0) return;

  for (int pass = 0; pass < 2; pass++) {
    uint8_t proto = pass == 0 ? IPPROTO_TCP : IPPROTO_UDP;
    uint32_t n = pass == 0 ? TABLE_SIZE_TCP : TABLE_SIZE_UDP;
    bucket_stat_t *arr = pass == 0 ? bucket_tcp : bucket_udp;

    for (uint32_t i = 0; i < n; i++) {
      bucket_stat_t *bs = &arr[i];
      if (!bs->initialized || bs->is_busy) continue;
      if (bs->last_empty_start_us == 0 || end_us < bs->last_empty_start_us) continue;

      uint64_t dur = end_us - bs->last_empty_start_us;
      bs->empty_periods++;
      bs->sum_empty_us += dur;

      if (g_bucket_empty_csv) {
        fprintf(g_bucket_empty_csv, "%s,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",pcap_end\n",
                proto_name_u8(proto), (unsigned)i,
                bs->last_empty_start_us, end_us, dur);
      }

      bs->last_empty_start_us = end_us;
    }
  }
}

static void write_bucket_summary_csv(const char *csv_path) {
  FILE *out = fopen(csv_path, "w");
  if (!out) { perror("fopen rc_bucket_mg1_summary.csv"); return; }

  fprintf(out,
          "proto,bucket_idx,"
          "total_eligible_arrivals,accepted_on_empty,arrivals_while_busy,"
          "challenger_wins,incumbent_wins,"
          "loss_model_exported_p_observed,loss_model_rejected_p_observed,"
          "exports_all,exports_ge_cap,exports_partial,"
          "busy_periods,mean_busy_us,min_busy_us,max_busy_us,"
          "lambda_per_sec,mg1_p_model,mg1_reject_model,"
          "empty_periods,sum_empty_us,sum_busy_us,observation_us\n");

  uint64_t obs_us = 0;
  if (g_first_pcap_ts_us != 0 && g_last_pcap_ts_us >= g_first_pcap_ts_us)
    obs_us = g_last_pcap_ts_us - g_first_pcap_ts_us;

  for (int pass = 0; pass < 2; pass++) {
    uint8_t proto = pass == 0 ? IPPROTO_TCP : IPPROTO_UDP;
    uint32_t n = pass == 0 ? TABLE_SIZE_TCP : TABLE_SIZE_UDP;
    bucket_stat_t *arr = pass == 0 ? bucket_tcp : bucket_udp;

    for (uint32_t i = 0; i < n; i++) {
      bucket_stat_t *bs = &arr[i];
      if (!bs->initialized || bs->total_eligible_arrivals == 0) continue;

      double mean_busy_us = bs->busy_periods ? (double)bs->sum_busy_us / (double)bs->busy_periods : 0.0;
      double lambda_per_sec = (obs_us > 0) ? ((double)bs->total_eligible_arrivals / ((double)obs_us / 1000000.0)) : 0.0;
      double mean_busy_sec = mean_busy_us / 1000000.0;
      double mg1_p = 1.0 / (1.0 + lambda_per_sec * mean_busy_sec);
      double mg1_rej = 1.0 - mg1_p;

      double p_obs = bs->total_eligible_arrivals ?
        (double)bs->accepted_on_empty / (double)bs->total_eligible_arrivals : 0.0;
      double r_obs = bs->total_eligible_arrivals ?
        (double)bs->arrivals_while_busy / (double)bs->total_eligible_arrivals : 0.0;

      uint64_t min_busy = (bs->min_busy_us == UINT64_MAX) ? 0 : bs->min_busy_us;

      fprintf(out,
              "%s,%u,"
              "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
              "%" PRIu64 ",%" PRIu64 ","
              "%.12f,%.12f,"
              "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
              "%" PRIu64 ",%.3f,%" PRIu64 ",%" PRIu64 ","
              "%.12f,%.12f,%.12f,"
              "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
              proto_name_u8(proto), (unsigned)i,
              bs->total_eligible_arrivals, bs->accepted_on_empty, bs->arrivals_while_busy,
              bs->challenger_wins, bs->incumbent_wins,
              p_obs, r_obs,
              bs->exports_all, bs->exports_ge_cap, bs->exports_partial,
              bs->busy_periods, mean_busy_us, min_busy, bs->max_busy_us,
              lambda_per_sec, mg1_p, mg1_rej,
              bs->empty_periods, bs->sum_empty_us, bs->sum_busy_us, obs_us);
    }
  }

  fclose(out);
}



static inline void ip_to_str(uint32_t ip, char out[INET_ADDRSTRLEN]) {
  inet_ntop(AF_INET, &ip, out, INET_ADDRSTRLEN);
}

static inline void log_collision_event(const struct timeval *tv,
                                       const flow_key_t *winner,
                                       const flow_key_t *loser,
                                       int winner_was_incumbent)
{
  if (!g_colbin) return;

  collision_rec_t r;
  r.winner = *winner;
  r.loser  = *loser;
  r.winner_was_incumbent = (uint8_t)(winner_was_incumbent ? 1 : 0);
  r.ts_us = tv_to_us(tv);

  (void)fwrite(&r, sizeof(r), 1, g_colbin);
  gt_note_collision(winner, loser);
}

static void write_collisions_csv_from_bin(const char *bin_path, const char *csv_path) {
  FILE *in = fopen(bin_path, "rb");
  if (!in) { perror("fopen rc_collisions.bin"); return; }

  FILE *out = fopen(csv_path, "w");
  if (!out) { perror("fopen rc_collisions.csv"); fclose(in); return; }

  fprintf(out,
    "ts_us,"
    "winner_ip1,winner_port1,winner_ip2,winner_port2,winner_proto,"
    "loser_ip1,loser_port1,loser_ip2,loser_port2,loser_proto,"
    "winner_was_incumbent,"
    "winner_pkts,loser_pkts,"
    "winner_ge40,loser_ge40\n"
  );

  collision_rec_t r;
  while (fread(&r, sizeof(r), 1, in) == 1) {
    char wip1[INET_ADDRSTRLEN], wip2[INET_ADDRSTRLEN];
    char lip1[INET_ADDRSTRLEN], lip2[INET_ADDRSTRLEN];
    ip_to_str(r.winner.ip1, wip1);
    ip_to_str(r.winner.ip2, wip2);
    ip_to_str(r.loser.ip1,  lip1);
    ip_to_str(r.loser.ip2,  lip2);

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
      r.ts_us,
      wip1, (unsigned)r.winner.port1, wip2, (unsigned)r.winner.port2, (r.winner.proto == IPPROTO_UDP ? "UDP" : "TCP"),
      lip1, (unsigned)r.loser.port1,  lip2, (unsigned)r.loser.port2,  (r.loser.proto  == IPPROTO_UDP ? "UDP" : "TCP"),
      (unsigned)r.winner_was_incumbent,
      (unsigned)wp, (unsigned)lp,
      w_ge, l_ge
    );
  }

  fclose(out);
  fclose(in);
}

/* UPDATED summary writer: includes dur_30_to_last_us */
static void write_flow_collision_summary_csv(const char *csv_path) {
  FILE *out = fopen(csv_path, "w");
  if (!out) { perror("fopen rc_flow_collision_summary.csv"); return; }

  fprintf(out,
          "ip1,port1,ip2,port2,proto,"
          "pkts,ge40,collisions,wins,losses,"
          "first_ts_us,hit30_ts_us,last_ts_us,"
          "dur_to_30_us,dur_30_to_last_us,dur_total_us\n");

  for (uint32_t i = 0; i < GT_SIZE; i++) {
    gt_entry_t *e = &gt_tab[i];
    if (!e->in_use) continue;

    char ip1[INET_ADDRSTRLEN], ip2[INET_ADDRSTRLEN];
    ip_to_str(e->key.ip1, ip1);
    ip_to_str(e->key.ip2, ip2);

    uint64_t dur_to_30 = 0;
    if (e->hit30_ts_us != 0 && e->first_ts_us != 0 && e->hit30_ts_us >= e->first_ts_us) {
      dur_to_30 = e->hit30_ts_us - e->first_ts_us;
    }

    uint64_t dur_30_to_last = 0;
    if (e->hit30_ts_us != 0 && e->last_ts_us != 0 && e->last_ts_us >= e->hit30_ts_us) {
      dur_30_to_last = e->last_ts_us - e->hit30_ts_us;
    }

    uint64_t dur_total = 0;
    if (e->last_ts_us != 0 && e->first_ts_us != 0 && e->last_ts_us >= e->first_ts_us) {
      dur_total = e->last_ts_us - e->first_ts_us;
    }

    fprintf(out,
      "%s,%u,%s,%u,%s,"
      "%u,%d,%u,%u,%u,"
      "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
      "%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
      ip1, (unsigned)e->key.port1,
      ip2, (unsigned)e->key.port2,
      (e->key.proto == IPPROTO_UDP ? "UDP" : "TCP"),
      (unsigned)e->pkt_count,
      (e->pkt_count >= FLOW_CAP) ? 1 : 0,
      (unsigned)e->collisions,
      (unsigned)e->wins,
      (unsigned)e->losses,
      e->first_ts_us,
      e->hit30_ts_us,
      e->last_ts_us,
      dur_to_30,
      dur_30_to_last,
      dur_total
    );
  }

  fclose(out);
}

/* ================================================================= */
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
static void tw_init(time_t start_sec) {
  for (int i = 0; i < TW_SLOTS; ++i) tw_head_udp[i] = -1;
  tw_now_sec = start_sec;
  tw_now_slot = (int)(start_sec % TW_SLOTS);
  tw_initialised = 1;
}

static void tw_remove_generic(flow_entry_t *base, int *tw_head, int idx)
{
  flow_entry_t *e = &base[idx];
  if (e->tw_slot < 0) return;

  int slot = e->tw_slot;

  if (e->tw_prev != -1) base[e->tw_prev].tw_next = e->tw_next;
  else                  tw_head[slot] = e->tw_next;

  if (e->tw_next != -1) base[e->tw_next].tw_prev = e->tw_prev;

  e->tw_slot = -1;
  e->tw_next = -1;
  e->tw_prev = -1;
}

static void tw_insert_generic(flow_entry_t *base, int *tw_head, int idx, time_t exp_sec)
{
  flow_entry_t *e = &base[idx];

  if (e->tw_slot >= 0) tw_remove_generic(base, tw_head, idx);

  int slot = (int)(exp_sec % TW_SLOTS);

  e->tw_slot = slot;
  e->tw_prev = -1;
  e->tw_next = tw_head[slot];

  if (tw_head[slot] != -1) base[tw_head[slot]].tw_prev = idx;
  tw_head[slot] = idx;
}

/* ================================================================= */
/*                       JSON encoding helpers                        */
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
    while (fill == 0 && !exiting) pthread_cond_wait(&cond_full, &mtx);

    if (exiting && fill == 0) { pthread_mutex_unlock(&mtx); break; }

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
static flow_key_t make_key(uint32_t s_ip, uint32_t d_ip, uint16_t s_pt,
                           uint16_t d_pt, uint8_t proto) {
  flow_key_t k;
  if (ntohl(s_ip) < ntohl(d_ip)) {
    k.ip1 = s_ip; k.ip2 = d_ip; k.port1 = s_pt; k.port2 = d_pt;
  } else if (ntohl(s_ip) > ntohl(d_ip)) {
    k.ip1 = d_ip; k.ip2 = s_ip; k.port1 = d_pt; k.port2 = s_pt;
  } else {
    k.ip1 = s_ip; k.ip2 = d_ip;
    if (s_pt > d_pt) { uint16_t t = s_pt; s_pt = d_pt; d_pt = t; }
    k.port1 = s_pt; k.port2 = d_pt;
  }
  k.proto = proto;
  return k;
}

/* ================================================================= */
/*                         CSV logging                                */
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
    ? "rc_flow_output_timing_wheel_udp.csv"
    : "rc_flow_output_timing_wheel_tcp.csv";

  FILE *f = fopen(fname, "a");
  if (!f) { perror("fopen"); exit(1); }
  fprintf(f, "%s,\"%s\"\n", input_field, feature_vector);
  fclose(f);
}

/* ================================================================= */
/*                     flow finalisation & output                     */
static void dump_and_clear(flow_entry_t *base, flow_entry_t *e, int *tw_head,
                           uint64_t clear_ts_us, const char *reason) {
  uint8_t proto = e->is_udp ? IPPROTO_UDP : IPPROTO_TCP;
  uint32_t bucket_idx = (uint32_t)idx_of(base, e);
  int ge_cap = (e->count >= FLOW_CAP);

  if (ge_cap) st_cap_flushes++;

  if (e->is_udp && base == table_udp) {
    tw_remove_generic(base, tw_head, (int)bucket_idx);
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

  bucket_transition_to_empty(proto, bucket_idx, clear_ts_us, reason, e->count, ge_cap);

  enqueue_flow(e);

  memset(e, 0, sizeof *e);
  e->tw_slot = e->tw_next = e->tw_prev = -1;
}

/* ================================================================= */
/*                 timing-wheel advance logic (UDP-only expiry)        */
static void expire_slot_list_udp(int slot) {
  int idx = tw_head_udp[slot];
  tw_head_udp[slot] = -1;

  while (idx != -1) {
    int nxt = table_udp[idx].tw_next;
    table_udp[idx].tw_slot = table_udp[idx].tw_next = -1;
    uint64_t clear_ts_us = (uint64_t)tw_now_sec * 1000000ull;
    dump_and_clear(table_udp, &table_udp[idx], tw_head_udp, clear_ts_us, "udp_idle");
    idx = nxt;
  }
}

static void tw_advance(time_t now_sec) {
  g_in_tw = 1;
  g_tw_now_arg = (sig_atomic_t)now_sec;

  if (!tw_initialised) tw_init(now_sec);

  if (now_sec <= tw_now_sec) { g_in_tw = 0; return; }

  time_t delta = now_sec - tw_now_sec;

  if (delta >= TW_SLOTS) {
    for (int s = 0; s < TW_SLOTS; ++s) expire_slot_list_udp(s);
    tw_now_sec  = now_sec;
    tw_now_slot = (int)(now_sec % TW_SLOTS);
    g_in_tw = 0;
    return;
  }

  while (tw_now_sec < now_sec) {
    tw_now_sec++;
    tw_now_slot = (tw_now_slot + 1) & (TW_SLOTS - 1);
    expire_slot_list_udp(tw_now_slot);
  }

  g_in_tw = 0;
}

/* ================================================================= */
/*                 packet tracking (called per packet)               */
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

/* Decide if we can admit a TCP flow using the TCP Bloom gate.
   Returns 1 if allowed (definitely-not-seen => inserted), 0 if refused. */
static inline int tcp_admission_allowed(const flow_key_t *key) {
  int seen = bloom_probably_seen_and_maybe_add(tcp_bloom,
                                               TCP_BLOOM_BITS,
                                               TCP_BLOOM_K,
                                               key,
                                               1);
  if (seen) { st_tcp_bloom_refused++; return 0; }
  return 1;
}

/* Decide if we can admit a UDP flow using the UDP Bloom gate.
   Returns 1 if allowed (definitely-not-seen => inserted), 0 if refused. */
static inline int udp_admission_allowed(const flow_key_t *key) {
  int seen = bloom_probably_seen_and_maybe_add(udp_bloom,
                                               UDP_BLOOM_BITS,
                                               UDP_BLOOM_K,
                                               key,
                                               1);
  if (seen) { st_udp_bloom_refused++; return 0; }
  return 1;
}

static void track_packet(const struct timeval *tv, uint32_t sip, uint32_t dip,
                         uint16_t sport, uint16_t dport, uint8_t proto,
                         uint16_t ip_len)
{
  uint64_t t_us = tv_to_us(tv);
  if (g_first_pcap_ts_us == 0) g_first_pcap_ts_us = t_us;
  g_last_pcap_ts_us = t_us;

  tw_advance(tv->tv_sec);

  flow_key_t key = make_key(sip, dip, sport, dport, proto);

  /* Ground-truth counts/timestamps: ALWAYS update for all packets */
  gt_count_packet_tv(&key, tv);

  char kbuf[64];
  snprintf(kbuf, sizeof kbuf, "%08x%04x%08x%04x%02x",
           key.ip1, key.port1, key.ip2, key.port2, key.proto);

  uint32_t h = fnv1a_32(kbuf);

  /* UPDATED: protocol-specific mask/index */
  flow_entry_t *base = (proto == IPPROTO_UDP) ? table_udp : table_tcp;
  uint32_t mask = (proto == IPPROTO_UDP) ? (TABLE_SIZE_UDP - 1u) : (TABLE_SIZE_TCP - 1u);
  uint32_t p = h & mask;

  int *tw_head = (proto == IPPROTO_UDP) ? tw_head_udp : NULL;
  flow_entry_t *m = &base[p];

  if (!m->in_use) {
    /* admission gating for NEW flows */
    if (proto == IPPROTO_TCP) {
      if (!tcp_admission_allowed(&key)) return;
    } else { /* UDP */
      if (!udp_admission_allowed(&key)) return;
    }

    /* New eligible flow arrival found an empty bucket. */
    bucket_note_arrival(proto, p, 1);
    bucket_transition_to_busy(proto, p, t_us);

    init_new_entry(m, key, sip, dip, sport, dport, proto);
    st_flows_inserted++;
  } else if (!compare_key(&m->key, &key)) {
    st_flows_matched++;
  } else {
    /* Collision opportunity in this slot: apply eligibility gating FIRST */
    if (proto == IPPROTO_TCP) {
      /* TCP: only a collision event if challenger passes Bloom */
      if (!tcp_admission_allowed(&key)) {
        /* Bloom refused => challenger dropped, not counted/logged */
        return;
      }
    } else {
      /* UDP: only a collision event if challenger passes Bloom */
      if (!udp_admission_allowed(&key)) {
        /* Bloom refused => challenger dropped, not counted/logged */
        return;
      }
    }

    /* New eligible flow arrival found a busy bucket. For the M/G/1
       loss model, this is a rejected/lost arrival. Under Random Chance, the
       implementation may still replace the incumbent; both cases are
       recorded separately below. */
    bucket_note_arrival(proto, p, 0);

    /* Now this qualifies as a collision event */
    st_collisions++;
    st_battles++;

    if (evict_prob_random_chance(m)) {
      /* Challenger wins: the arriving flow replaces the incumbent.
         The bucket remains busy, so this does NOT end the busy period. */
      st_challenger_wins++;
      bucket_note_challenger_win(proto, p);
      log_collision_event(tv, &key, &m->key, 0);

      if (proto == IPPROTO_UDP && tw_head != NULL) {
        tw_remove_generic(base, tw_head, (int)p);
      }

      init_new_entry(m, key, sip, dip, sport, dport, proto);
      st_flows_inserted++;
    } else {
      /* Incumbent wins: the arriving challenger is rejected. */
      st_incumbent_wins++;
      bucket_note_incumbent_win(proto, p);
      m->wins++;
      log_collision_event(tv, &m->key, &key, 1);
      return;
    }
  }

  /* Track packet into the (current) resident entry */
  if (m->count < FLOW_CAP) {
    int from_cli = (sip == m->cli_ip && sport == m->cli_port);
    m->ts[m->count] = *tv;
    m->len[m->count] = (from_cli ? +1 : -1) * (int32_t)ip_len;
    m->count++;
    st_packets_tracked++;
  }

  if (proto == IPPROTO_UDP && tw_head != NULL) {
    tw_insert_generic(base, tw_head, (int)p, tv->tv_sec + UDP_IDLE_SEC);
  }

  if (m->count == FLOW_CAP) {
    dump_and_clear(base, m, tw_head, t_us, "cap");
  }
}

/* ================================================================= */
/*                parse Ethernet/IP/TCP/UDP & call tracker            */
static int parse_and_track(const struct pcap_pkthdr *h, const u_char *pkt) {
  const struct ether_header *eth = (const struct ether_header *)pkt;
  if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;

  const struct ip *ip = (const struct ip *)(pkt + sizeof *eth);
  uint8_t proto = ip->ip_p;
  uint32_t sip = ip->ip_src.s_addr, dip = ip->ip_dst.s_addr;

  uint16_t sport = 0, dport = 0;
  int ip_hl = ip->ip_hl * 4;

  if (proto == IPPROTO_TCP) {
    const struct tcphdr *th = (const struct tcphdr *)(pkt + sizeof *eth + ip_hl);
    sport = ntohs(th->th_sport);
    dport = ntohs(th->th_dport);

    /* TCP admission is Bloom-filter based, not SYN-flag based. */
  } else if (proto == IPPROTO_UDP) {
    const struct udphdr *uh = (const struct udphdr *)(pkt + sizeof *eth + ip_hl);
    sport = ntohs(uh->uh_sport);
    dport = ntohs(uh->uh_dport);
  } else {
    return 0;
  }

  last_pcap_sec = h->ts.tv_sec;
  track_packet(&h->ts, sip, dip, sport, dport, proto, ntohs(ip->ip_len));
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
int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s file.pcap [seed]\n", argv[0]);
    return 1;
  }
  signal(SIGQUIT, on_sigquit);

  uint32_t seed = 123456789u;
  if (argc == 3) seed = (uint32_t)strtoul(argv[2], NULL, 10);
  rng_seed(seed);
  fprintf(stderr, "RNG seed=%u\n", seed);
  fprintf(stderr, "TABLE_SIZE_TCP=%u TABLE_SIZE_UDP=%u\n",
          (unsigned)TABLE_SIZE_TCP, (unsigned)TABLE_SIZE_UDP);

  tcp_bloom_clear();
  udp_bloom_clear();
  for (int i = 0; i < TW_SLOTS; ++i) tw_head_udp[i] = -1;
  memset(gt_tab, 0, sizeof(gt_tab));
  bucket_stats_init_all();

  g_colbin = fopen("rc_collisions.bin", "wb");
  if (!g_colbin) { perror("fopen rc_collisions.bin"); return 1; }

  open_bucket_period_csvs();

  char err[PCAP_ERRBUF_SIZE];
  fprintf(stderr, "main: starting\n");
  pcap_t *pc = pcap_open_offline(argv[1], err);
  if (!pc) {
    fprintf(stderr, "pcap_open: %s\n", err);
    fclose(g_colbin);
    return 1;
  }
  fprintf(stderr, "main: pcap opened\n");

  if (pthread_create(&zmq_thread, NULL, sender_thread, NULL) != 0) {
    perror("pthread_create");
    pcap_close(pc);
    fclose(g_colbin);
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
      fprintf(stderr, "pcap: pkts=%" PRIu64 " iters=%" PRIu64 " last_ts=%ld\n",
              pkts, iters, (long)h->ts.tv_sec);
    }

    parse_and_track(h, pkt);
  }

  if (rc == -1) fprintf(stderr, "pcap error: %s\n", pcap_geterr(pc));
  fprintf(stderr, "main: pcap loop done rc=%d\n", rc);

  if (last_pcap_sec != 0) tw_advance(last_pcap_sec + UDP_IDLE_SEC + TW_SLOTS);

  /* UPDATED: flush each table using its own size */
  for (uint32_t i = 0; i < TABLE_SIZE_TCP; ++i) {
    if (table_tcp[i].in_use) dump_and_clear(table_tcp, &table_tcp[i], NULL, g_last_pcap_ts_us, "pcap_end");
  }
  for (uint32_t i = 0; i < TABLE_SIZE_UDP; ++i) {
    if (table_udp[i].in_use) dump_and_clear(table_udp, &table_udp[i], tw_head_udp, g_last_pcap_ts_us, "pcap_end");
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
          " tcp_bloom_refused=%" PRIu64
          " udp_bloom_refused=%" PRIu64 " cap_flushes=%" PRIu64 "\n",
          st_flows_inserted, st_flows_matched,
          st_packets_tracked,
          st_collisions, st_battles,
          st_challenger_wins, st_incumbent_wins,
          st_tcp_bloom_refused,
          st_udp_bloom_refused, st_cap_flushes);

  fclose(g_colbin);
  g_colbin = NULL;

  write_collisions_csv_from_bin("rc_collisions.bin", "rc_collisions.csv");
  write_flow_collision_summary_csv("rc_flow_collision_summary.csv");

  bucket_finalize_empty_periods(g_last_pcap_ts_us);
  write_bucket_summary_csv("rc_bucket_mg1_summary.csv");
  close_bucket_period_csvs();

  return 0;
}