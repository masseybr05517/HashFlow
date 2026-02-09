/*********************************************************************
 *  flowhash_pcap_benchmark_bloom.c
 *
 *  Based on: flowhash_zmq_timing_wheel_reservoir_bloom.c
 *
 *  Changes:
 *   - NO CSV output
 *   - NO ZMQ / JSON / sender thread
 *   - Runs the same input PCAP RUNS times (default 1000)
 *   - For each run: counts how many flows would have been written to CSV
 *       (i.e., flows that reach FLOW_CAP and are dumped)
 *   - Outputs mean, 25th percentile, 75th percentile (nearest-rank)
 *********************************************************************/

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---------- parameters ------------------------------------------- */
#define TABLE_SIZE (8192) /* must be power of 2 */
#define FLOW_CAP 40       /* pkts per flow      */
#define UDP_IDLE_SEC 30   /* idle timeout UDP   */
#define TW_SLOTS 256      /* must be power of 2 */

#define RUNS_DEFAULT 1000

/* ---------- UDP Bloom filter (UDP-only admission gate) ------------ */
/* Bits must be power-of-two for fast masking.                        */
/* 2^28 bits = 32MB                                                    */
#define UDP_BLOOM_BITS   (1u << 28)
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
static inline void udp_bloom_clear(void) { memset(udp_bloom, 0, sizeof udp_bloom); }

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
  int32_t len[FLOW_CAP]; /* sign encodes direction, magnitude is ip_len */
  int count;

  /* collision wins (kept for parity; affects probability if you later restore reservoir) */
  uint32_t wins;

  /* --- timing-wheel bookkeeping (UDP-only) --- */
  int tw_next;
  int tw_prev;
  int tw_slot;
} flow_entry_t;

static inline int idx_of(flow_entry_t *base, flow_entry_t *e) { return (int)(e - base); }

/* Returns 1 if "probably seen", 0 if "definitely not seen".
   If add_if_new=1 and definitely-not-seen, also inserts into bloom. */
static inline int udp_bloom_probably_seen_and_maybe_add(const flow_key_t *k, int add_if_new) {
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
static flow_entry_t table_tcp[TABLE_SIZE];
static flow_entry_t table_udp[TABLE_SIZE];

/* ================================================================= */
/*                           Timing-wheel (UDP-only)                  */
/* ================================================================= */
static int tw_head_udp[TW_SLOTS];

static time_t tw_now_sec = 0;
static int tw_now_slot = 0;
static int tw_initialised = 0;
static time_t last_pcap_sec = 0;

/* ================================================================= */
/*                       "would-have-written-to-CSV" counter          */
/* ================================================================= */
static uint64_t g_flowcap_dumps = 0;

/* ================================================================= */
/*                           Timing-wheel helpers                     */
/* ================================================================= */
static void tw_init(time_t start_sec) {
  for (int i = 0; i < TW_SLOTS; ++i) tw_head_udp[i] = -1;
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

  if (e->tw_slot >= 0) tw_remove_generic(base, tw_head, idx);

  int slot = (int)(exp_sec % TW_SLOTS);

  e->tw_slot = slot;
  e->tw_prev = -1;
  e->tw_next = tw_head[slot];

  if (tw_head[slot] != -1) base[tw_head[slot]].tw_prev = idx;

  tw_head[slot] = idx;
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

/* challenger replaces incumbent with 50/50 probability */
static inline int challenger_wins_50_50(void) {
  return ((uint32_t)rand() % 2u) == 0u;
}

/* Decide if we can admit a UDP flow (Bloom gate). Returns 1 if allowed, 0 if refused. */
static inline int udp_admission_allowed(const flow_key_t *key) {
  int seen = udp_bloom_probably_seen_and_maybe_add(key, /*add_if_new=*/1);
  if (seen) return 0;
  return 1;
}

/* ================================================================= */
/*                     flow finalisation & "counting"                 */
/* ================================================================= */
static void dump_and_clear(flow_entry_t *base, flow_entry_t *e, int *tw_head) {
  if (e->is_udp && base == table_udp) {
    int idx = idx_of(base, e);
    tw_remove_generic(base, tw_head, idx);
  }

  /* This is the key: count exactly what CSV-writing would have counted */
  if (e->count == FLOW_CAP) {
    g_flowcap_dumps++;
  }

  memset(e, 0, sizeof *e);
  e->tw_slot = e->tw_next = e->tw_prev = -1;
}

/* ================================================================= */
/*                 timing-wheel advance logic (UDP-only expiry)       */
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
  if (!tw_initialised) tw_init(now_sec);

  if (now_sec <= tw_now_sec) return;

  time_t delta = now_sec - tw_now_sec;

  /* BIG JUMP: expire everything UDP */
  if (delta >= TW_SLOTS) {
    for (int s = 0; s < TW_SLOTS; ++s) expire_slot_list_udp(s);
    tw_now_sec  = now_sec;
    tw_now_slot = (int)(now_sec % TW_SLOTS);
    return;
  }

  /* step */
  while (tw_now_sec < now_sec) {
    tw_now_sec++;
    tw_now_slot = (tw_now_slot + 1) & (TW_SLOTS - 1);
    expire_slot_list_udp(tw_now_slot);
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

  e->wins = 0;
  e->tw_slot = e->tw_next = e->tw_prev = -1;
}

static void track_packet(const struct timeval *tv, uint32_t sip, uint32_t dip,
                         uint16_t sport, uint16_t dport, uint8_t proto,
                         int tcp_syn, uint16_t ip_len) {
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

  } else if (!compare_key(&m->key, &key)) {
    /* match: do nothing special */

  } else {
    /* collision with incumbent */
    if (proto == IPPROTO_TCP && !tcp_syn) return;

    /* 50/50 random replacement */
    if (challenger_wins_50_50()) {
      /* Challenger would replace incumbent: apply UDP bloom gate first */
      if (proto == IPPROTO_UDP) {
        if (!udp_admission_allowed(&key)) {
          /* refused -> challenger dropped; incumbent remains */
          return;
        }
      }

      /* remove incumbent from wheel if UDP */
      if (proto == IPPROTO_UDP && tw_head != NULL) {
        int idx = (int)p;
        tw_remove_generic(base, tw_head, idx);
      }

      init_new_entry(m, key, sip, dip, sport, dport, proto);
    } else {
      /* incumbent stays */
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

/* ================================================================= */
/*                      run reset + one simulation run                */
/* ================================================================= */
static void reset_state_for_run(void) {
  memset(table_tcp, 0, sizeof table_tcp);
  memset(table_udp, 0, sizeof table_udp);

  for (int i = 0; i < TW_SLOTS; ++i) tw_head_udp[i] = -1;

  udp_bloom_clear();

  tw_now_sec = 0;
  tw_now_slot = 0;
  tw_initialised = 0;
  last_pcap_sec = 0;

  g_flowcap_dumps = 0;
}

static uint64_t run_once_on_pcap(const char *pcap_path) {
  reset_state_for_run();

  char err[PCAP_ERRBUF_SIZE];
  pcap_t *pc = pcap_open_offline(pcap_path, err);
  if (!pc) {
    fprintf(stderr, "pcap_open_offline: %s\n", err);
    exit(1);
  }

  struct pcap_pkthdr *h;
  const u_char *pkt;
  int rc;

  while ((rc = pcap_next_ex(pc, &h, &pkt)) >= 0) {
    if (rc == 0) continue;
    parse_and_track(h, pkt);
  }
  if (rc == -1) fprintf(stderr, "pcap error: %s\n", pcap_geterr(pc));

  /* final flush: advance far enough to expire all UDP flows */
  if (last_pcap_sec != 0) {
    tw_advance(last_pcap_sec + UDP_IDLE_SEC + TW_SLOTS);
  }

  /* flush both tables (these will only count if count==FLOW_CAP) */
  for (int i = 0; i < TABLE_SIZE; ++i) {
    if (table_tcp[i].in_use) dump_and_clear(table_tcp, &table_tcp[i], NULL);
    if (table_udp[i].in_use) dump_and_clear(table_udp, &table_udp[i], tw_head_udp);
  }

  pcap_close(pc);
  return g_flowcap_dumps;
}

/* ================================================================= */
/*                 stats helpers: mean + nearest-rank percentiles      */
/* ================================================================= */
static int cmp_u64(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a;
  uint64_t y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}

/* nearest-rank percentile:
   rank = ceil(p * n), with p in [0,1], ranks 1..n */
static uint64_t percentile_nearest_rank(const uint64_t *sorted, size_t n, double p) {
  if (n == 0) return 0;
  if (p <= 0.0) return sorted[0];
  if (p >= 1.0) return sorted[n - 1];
  double r = p * (double)n;
  size_t rank = (size_t)(r);
  if (r > (double)rank) rank++; /* ceil */
  if (rank < 1) rank = 1;
  if (rank > n) rank = n;
  return sorted[rank - 1];
}

int main(int argc, char **argv) {
  if (argc != 2 && argc != 3) {
    fprintf(stderr, "usage: %s file.pcap [runs]\n", argv[0]);
    return 1;
  }

  int runs = RUNS_DEFAULT;
  if (argc == 3) {
    runs = atoi(argv[2]);
    if (runs <= 0) {
      fprintf(stderr, "runs must be positive\n");
      return 1;
    }
  }

  const char *pcap_path = argv[1];

  /* Seed once; each run uses rand() for the 50/50 replacement */
  srand((unsigned)time(NULL));

  uint64_t *counts = (uint64_t *)calloc((size_t)runs, sizeof(uint64_t));
  if (!counts) {
    perror("calloc");
    return 1;
  }

  long double sum = 0.0L;

  for (int i = 0; i < runs; i++) {
    /* Optional: perturb RNG per run to avoid identical sequences if time() granularity is coarse */
    (void)rand();

    uint64_t c = run_once_on_pcap(pcap_path);
    counts[i] = c;
    sum += (long double)c;
  }

  qsort(counts, (size_t)runs, sizeof(uint64_t), cmp_u64);

  long double mean = sum / (long double)runs;
  uint64_t p25 = percentile_nearest_rank(counts, (size_t)runs, 0.25);
  uint64_t p75 = percentile_nearest_rank(counts, (size_t)runs, 0.75);

  printf("runs=%d\n", runs);
  printf("mean_flows=%0.6Lf (rounded=%" PRIu64 ")\n", mean, (uint64_t)(mean + 0.5L));
  printf("p25=%" PRIu64 "\n", p25);
  printf("p75=%" PRIu64 "\n", p75);

  free(counts);
  return 0;
}
