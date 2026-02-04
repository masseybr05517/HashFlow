/*********************************************************************
 *  hashflow_option2_records_in_M_and_A.c
 *
 *  HashFlow Algorithm-1 control logic (probe h1..hd in M, sentinel min/pos,
 *  fall back to A at g1, replace/increment/promotion), BUT with "Option 2":
 *
 *   - BOTH M and A store FULL flowID (5-tuple) + your per-packet record arrays
 *     (timestamps + signed ip_len), up to FLOW_CAP packets.
 *   - This keeps record correctness (no digest collision ambiguity in A).
 *   - NOTE: This deviates from the paper’s memory-saving design for A
 *     (paper uses digest in A), but preserves the HashFlow control flow.
 *
 *  Output:
 *   - hashflow_opt2_main.csv   (one line per occupied M entry)
 *   - hashflow_opt2_aux.csv    (one line per occupied A entry)
 *
 *  Build:
 *    gcc -O3 -Wall -Wextra -pedantic -std=c11 \
 *      hashflow_option2_records_in_M_and_A.c -lpcap -o hashflow_opt2
 *
 *  Run:
 *    ./hashflow_opt2 input.pcap
 *********************************************************************/

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------- Tunables -------------------- */
#define FLOW_CAP   40

/* HashFlow table sizes (power-of-two) */
#define M_SIZE     (1u << 20)   /* main table buckets */
#define A_SIZE     (1u << 18)   /* auxiliary table buckets */

/* HashFlow depth d: number of independent hashes into M */
#define DEPTH_D    3            /* typical is 3 */

/* Debug prints */
#define SHOW_STATS 1

/* -------------------- Guards -------------------- */
#if (M_SIZE & (M_SIZE - 1)) != 0
#error "M_SIZE must be a power of two"
#endif
#if (A_SIZE & (A_SIZE - 1)) != 0
#error "A_SIZE must be a power of two"
#endif
#if (DEPTH_D < 1)
#error "DEPTH_D must be >= 1"
#endif
#if (DEPTH_D > 8)
#error "DEPTH_D too large for built-in seeds (max 8)"
#endif

/* -------------------- FlowID (5-tuple) -------------------- */
typedef struct {
  uint32_t sip;
  uint32_t dip;
  uint16_t sport;
  uint16_t dport;
  uint8_t  proto; /* IPPROTO_TCP / IPPROTO_UDP */
} flowid_t;

static inline int flowid_eq(const flowid_t *a, const flowid_t *b) {
  return a->sip == b->sip && a->dip == b->dip &&
         a->sport == b->sport && a->dport == b->dport &&
         a->proto == b->proto;
}

/* -------------------- Hashing -------------------- */
static inline uint32_t mix32(uint32_t x) {
  x ^= x >> 16;
  x *= 0x7feb352du;
  x ^= x >> 15;
  x *= 0x846ca68bu;
  x ^= x >> 16;
  return x;
}

static inline uint32_t hash_flowid_seeded(const flowid_t *f, uint32_t seed) {
  uint32_t h = seed;
  h ^= mix32(f->sip);
  h ^= mix32(f->dip);
  h ^= mix32(((uint32_t)f->sport << 16) | (uint32_t)f->dport);
  h ^= mix32((uint32_t)f->proto);
  return mix32(h);
}

/* Seeds for h1..hd (M) and g1 (A) */
static const uint32_t H_SEEDS[8] = {
  0x1234ABCDu, 0xBADC0FFEu, 0xC001D00Du, 0x9E3779B9u,
  0x7F4A7C15u, 0xD1B54A35u, 0x94D049BBu, 0xA24BAEDFu
};
static const uint32_t G1_SEED = 0xDEADBEEFu;

static inline uint32_t h_i_idx(const flowid_t *fid, int i /* 1..d */) {
  uint32_t h = hash_flowid_seeded(fid, H_SEEDS[i - 1]);
  return h & (M_SIZE - 1);
}

static inline uint32_t g1_idx(const flowid_t *fid) {
  uint32_t h = hash_flowid_seeded(fid, G1_SEED);
  return h & (A_SIZE - 1);
}

/* -------------------- Record stored in BOTH M and A -------------------- */
typedef struct {
  int in_use;

  flowid_t key;

  /* HashFlow counter used for decisions (min/sentinel/promotion) */
  uint32_t count_total;

  /* Your per-packet feature capture (first FLOW_CAP packets recorded) */
  struct timeval ts[FLOW_CAP];
  int32_t len[FLOW_CAP];   /* signed: +ip_len if from first-packet direction, else -ip_len */
  uint32_t rec_n;          /* number recorded into ts/len, <= FLOW_CAP */

  /* Orientation (first-packet perspective) for signed direction */
  uint32_t cli_ip, srv_ip;
  uint16_t cli_port, srv_port;
} flow_record_t;

static flow_record_t M[M_SIZE];
static flow_record_t A[A_SIZE];

/* -------------------- Stats -------------------- */
static uint64_t st_pkts_total = 0;
static uint64_t st_M_insert = 0;
static uint64_t st_M_hit = 0;
static uint64_t st_M_collisions = 0;

static uint64_t st_A_replace = 0;
static uint64_t st_A_hit_inc = 0;
static uint64_t st_promotions = 0;

/* -------------------- Recording helpers -------------------- */
static inline void record_packet(flow_record_t *r,
                                 const struct timeval *tv,
                                 uint32_t sip, uint32_t dip,
                                 uint16_t sport, uint16_t dport,
                                 uint16_t ip_len)
{
  /* establish orientation on first ever packet for this record */
  if (r->count_total == 0) {
    r->cli_ip = sip; r->srv_ip = dip;
    r->cli_port = sport; r->srv_port = dport;
  }

  if (r->rec_n < FLOW_CAP) {
    int from_cli = (sip == r->cli_ip && sport == r->cli_port);
    r->ts[r->rec_n] = *tv;
    r->len[r->rec_n] = (from_cli ? +1 : -1) * (int32_t)ip_len;
    r->rec_n++;
  }
}

static inline void init_record(flow_record_t *r,
                               const flowid_t *fid,
                               const struct timeval *tv,
                               uint32_t sip, uint32_t dip,
                               uint16_t sport, uint16_t dport,
                               uint16_t ip_len)
{
  memset(r, 0, sizeof(*r));
  r->in_use = 1;
  r->key = *fid;
  r->count_total = 1;
  r->rec_n = 0;

  /* set orientation immediately (first packet) */
  r->cli_ip = sip; r->srv_ip = dip;
  r->cli_port = sport; r->srv_port = dport;

  record_packet(r, tv, sip, dip, sport, dport, ip_len);
}

/* -------------------- HashFlow Algorithm-1 control flow (Option 2) -------------------- */
/*
 * Inputs include packet metadata so we can store ts/len like your pipeline.
 *
 * Faithful control logic:
 *  - Probe M at h1..hd:
 *      if empty -> insert count=1 return
 *      if match -> count++ return
 *      else track sentinel = smallest count among collided cells
 *  - Else go to A at idxA=g1(flowID):
 *      if empty OR mismatch -> replace with count=1 return
 *      else if A.count < min -> A.count++ return
 *      else promote: M[pos] = flowID with count = A.count + 1
 *
 * Option 2 change:
 *  - A key match uses FULL flowID, not digest.
 *  - A stores record arrays too.
 */
static void hashflow_update_with_records(const flowid_t *flowID,
                                         const struct timeval *tv,
                                         uint32_t sip, uint32_t dip,
                                         uint16_t sport, uint16_t dport,
                                         uint16_t ip_len)
{
  uint32_t min = UINT32_MAX;
  uint32_t pos = UINT32_MAX;

  /* probe h1..hd in M */
  for (int i = 1; i <= DEPTH_D; i++) {
    uint32_t idx = h_i_idx(flowID, i);

    if (!M[idx].in_use) {
      init_record(&M[idx], flowID, tv, sip, dip, sport, dport, ip_len);
      st_M_insert++;
      return;
    }

    if (flowid_eq(&M[idx].key, flowID)) {
      M[idx].count_total++;
      record_packet(&M[idx], tv, sip, dip, sport, dport, ip_len);
      st_M_hit++;
      return;
    }

    st_M_collisions++;
    if (M[idx].count_total < min) {
      min = M[idx].count_total;
      pos = idx;
    }
  }

  /* unresolved in M -> go to A */
  uint32_t idxA = g1_idx(flowID);

  if (!A[idxA].in_use || !flowid_eq(&A[idxA].key, flowID)) {
    /* replace */
    init_record(&A[idxA], flowID, tv, sip, dip, sport, dport, ip_len);
    st_A_replace++;
    return;
  }

  /* A match */
  if (A[idxA].count_total < min) {
    A[idxA].count_total++;
    record_packet(&A[idxA], tv, sip, dip, sport, dport, ip_len);
    st_A_hit_inc++;
    return;
  }

  /* promotion */
  if (pos != UINT32_MAX) {
    /* Copy A record into M[pos], then apply HashFlow promotion count rule */
    flow_record_t promoted = A[idxA];
    promoted.in_use = 1;
    promoted.key = *flowID;

    /* faithful: new M count = A.count + 1 */
    promoted.count_total = A[idxA].count_total + 1;

    /* This arrival packet triggers the promotion. In Algorithm 1, the packet is “counted”.
       We did NOT increment A in this branch, so record it into promoted now. */
    record_packet(&promoted, tv, sip, dip, sport, dport, ip_len);

    M[pos] = promoted;
    st_promotions++;

    /* Paper does not require clearing A on promotion; leaving it is closer to “don’t specify”.
       If you want “move not copy”, uncomment next line:
       A[idxA].in_use = 0;
    */
    return;
  }

  /* fallback (should be rare) */
  A[idxA].count_total++;
  record_packet(&A[idxA], tv, sip, dip, sport, dport, ip_len);
  st_A_hit_inc++;
}

/* -------------------- CSV output (vector style like your code) -------------------- */
static void write_record_csv_line(FILE *f, const flow_record_t *r) {
  char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &r->key.sip, sip, sizeof(sip));
  inet_ntop(AF_INET, &r->key.dip, dip, sizeof(dip));

  /* input_field similar to your format */
  char input_field[256];
  snprintf(input_field, sizeof(input_field), "%s%u%s%u%s",
           sip, (unsigned)r->key.sport,
           dip, (unsigned)r->key.dport,
           (r->key.proto == IPPROTO_UDP) ? "UDP" : "TCP");

  /* feature vector [(t, len), ...] with sign convention like your code */
  char feature_vector[8192];
  size_t w = 0;
  w += (size_t)snprintf(feature_vector + w, sizeof(feature_vector) - w, "[");

  if (r->rec_n > 0) {
    double ts0 = r->ts[0].tv_sec + r->ts[0].tv_usec / 1e6;
    for (uint32_t i = 0; i < r->rec_n; i++) {
      double ts = r->ts[i].tv_sec + r->ts[i].tv_usec / 1e6;
      double offset = ts - ts0;

      /* In your code, you flip sign of time offset based on direction (len<0) */
      if (r->len[i] < 0) offset *= -1;

      w += (size_t)snprintf(feature_vector + w, sizeof(feature_vector) - w,
                            "(%.6f, %.1f)%s",
                            offset, (double)r->len[i],
                            (i + 1 < r->rec_n) ? ", " : "");
      if (w >= sizeof(feature_vector)) break;
    }
  }

  if (w < sizeof(feature_vector)) {
    (void)snprintf(feature_vector + w, sizeof(feature_vector) - w, "]");
  } else {
    /* ensure termination */
    feature_vector[sizeof(feature_vector) - 2] = ']';
    feature_vector[sizeof(feature_vector) - 1] = '\0';
  }

  fprintf(f, "%s,%" PRIu32 ",\"%s\"\n", input_field, r->count_total, feature_vector);
}

static void dump_table_csv(const char *fname, const flow_record_t *tab, uint32_t n) {
  FILE *f = fopen(fname, "w");
  if (!f) { perror("fopen"); exit(1); }

  /* header */
  fprintf(f, "flowid,count_total,features\n");

  for (uint32_t i = 0; i < n; i++) {
    if (!tab[i].in_use) continue;
    if (tab[i].rec_n == 0) continue; /* nothing recorded */
    write_record_csv_line(f, &tab[i]);
  }
  fclose(f);
}

/* -------------------- Packet parse -------------------- */
static int parse_to_flowid_and_meta(const struct pcap_pkthdr *h,
                                    const u_char *pkt,
                                    flowid_t *out,
                                    uint32_t *sip, uint32_t *dip,
                                    uint16_t *sport, uint16_t *dport,
                                    uint8_t *proto,
                                    uint16_t *ip_len)
{
  const struct ether_header *eth = (const struct ether_header *)pkt;
  if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;

  const struct ip *ip = (const struct ip *)(pkt + sizeof(*eth));
  *proto = ip->ip_p;
  if (*proto != IPPROTO_TCP && *proto != IPPROTO_UDP) return 0;

  int ip_hl = ip->ip_hl * 4;
  *sip = ip->ip_src.s_addr;
  *dip = ip->ip_dst.s_addr;
  *ip_len = ntohs(ip->ip_len);

  if (*proto == IPPROTO_TCP) {
    const struct tcphdr *th = (const struct tcphdr *)(pkt + sizeof(*eth) + ip_hl);
    *sport = ntohs(th->th_sport);
    *dport = ntohs(th->th_dport);
  } else {
    const struct udphdr *uh = (const struct udphdr *)(pkt + sizeof(*eth) + ip_hl);
    *sport = ntohs(uh->uh_sport);
    *dport = ntohs(uh->uh_dport);
  }

  out->sip = *sip;
  out->dip = *dip;
  out->sport = *sport;
  out->dport = *dport;
  out->proto = *proto;

  (void)h; /* we use h->ts directly in main loop */
  return 1;
}

/* -------------------- main -------------------- */
int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s file.pcap\n", argv[0]);
    return 1;
  }

  memset(M, 0, sizeof(M));
  memset(A, 0, sizeof(A));

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pc = pcap_open_offline(argv[1], errbuf);
  if (!pc) {
    fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
    return 1;
  }

  struct pcap_pkthdr *h;
  const u_char *pkt;
  int rc;

  flowid_t fid;
  uint32_t sip, dip;
  uint16_t sport, dport;
  uint8_t proto;
  uint16_t ip_len;

  while ((rc = pcap_next_ex(pc, &h, &pkt)) >= 0) {
    if (rc == 0) continue;

    st_pkts_total++;

    if (parse_to_flowid_and_meta(h, pkt, &fid, &sip, &dip, &sport, &dport, &proto, &ip_len)) {
      hashflow_update_with_records(&fid, &h->ts, sip, dip, sport, dport, ip_len);
    }
  }

  if (rc == -1) fprintf(stderr, "pcap error: %s\n", pcap_geterr(pc));
  pcap_close(pc);

  dump_table_csv("hashflow_opt2_main.csv", M, M_SIZE);
  dump_table_csv("hashflow_opt2_aux.csv",  A, A_SIZE);

#if SHOW_STATS
  fprintf(stderr,
          "HashFlow Option2 (records in M and A) stats:\n"
          "  pkts_total=%" PRIu64 "\n"
          "  M_insert=%" PRIu64 " M_hit=%" PRIu64 " M_collisions=%" PRIu64 "\n"
          "  A_replace=%" PRIu64 " A_hit_inc=%" PRIu64 " promotions=%" PRIu64 "\n",
          st_pkts_total,
          st_M_insert, st_M_hit, st_M_collisions,
          st_A_replace, st_A_hit_inc, st_promotions);
#endif

  return 0;
}
