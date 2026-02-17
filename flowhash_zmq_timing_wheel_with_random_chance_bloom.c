/*********************************************************************
 * flowhash_zmq_timing_wheel_random_chance_bloom_seeded.c
 *
 * Random eviction (p=0.5) + deterministic xorshift32 RNG + UDP Bloom gate
 * + collision logging + ground-truth per-flow summary.
 *
 * UPDATE (your request):
 * - Different table sizes for TCP vs UDP
 *     TCP table size = TABLE_SIZE_TCP
 *     UDP table size = TABLE_SIZE_UDP = TABLE_SIZE_TCP / 4
 *
 * Usage:
 *   ./prog file.pcap [seed]
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
#define TABLE_SIZE_TCP (4096) /* must be power of 2 */
#define TABLE_SIZE_UDP (TABLE_SIZE_TCP / 4) /* must be power of 2 */
#define FLOW_CAP 40         /* pkts per flow tracked in table */
#define UDP_IDLE_SEC 30     /* idle timeout UDP */
#define TW_SLOTS 256        /* must be power of 2 */
#define BUF_MAX 64          /* ring buffer slots */
#define BATCH_SIZE 16       /* flows per JSON msg */
#define SHOW_OUTPUT 0       /* stderr debug prints */
#define WRITE_TO_CSV 1      /* ZMQ shutdown / blocking behavior */
#define ZMQ_LINGER_MS 0
#define ZMQ_SNDTIMEO_MS 100
#define ZMQ_ENDPOINT "ipc:///tmp/flowpipe"

/* ---------- UDP Bloom filter (UDP-only admission gate) ------------ */
#define UDP_BLOOM_BITS (1u << 28)
#define UDP_BLOOM_BYTES (UDP_BLOOM_BITS / 8u)
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

/* ---------- time helpers ------------------------------------------ */
static inline uint64_t tv_to_us(const struct timeval *tv) {
    return (uint64_t)tv->tv_sec * 1000000ull + (uint64_t)tv->tv_usec;
}

/* ---------- bloom helpers ----------------------------------------- */
static inline void udp_bloom_clear(void) { memset(udp_bloom, 0, sizeof udp_bloom); }
static inline void bloom_set_bit(uint32_t bit) { udp_bloom[bit >> 3] |= (uint8_t)(1u << (bit & 7u)); }
static inline int bloom_get_bit(uint32_t bit) { return (udp_bloom[bit >> 3] >> (bit & 7u)) & 1u; }
static inline uint32_t mix32(uint32_t x) {
    x ^= x >> 16; x *= 0x7feb352du;
    x ^= x >> 15; x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

/* ---------- flow key / entry ------------------------------------- */
typedef struct {
    uint32_t ip1, ip2;      /* canonical src/dst order */
    uint16_t port1, port2;
    uint8_t proto;          /* IPPROTO_TCP | IPPROTO_UDP */
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

    uint32_t wins;          /* incumbent wins counter */

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
 * If add_if_new=1 and definitely-not-seen, also inserts into bloom. */
static inline int udp_bloom_probably_seen_and_maybe_add(const flow_key_t *k, int add_if_new) {
    uint32_t h1 = 2166136261u;
    h1 ^= (uint32_t)k->ip1;  h1 *= 16777619u;
    h1 ^= (uint32_t)k->ip2;  h1 *= 16777619u;
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
            return 0;
        }
    }
    return 1;
}

/* ================================================================= */
/* Deterministic RNG (xorshift32) */
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
/* one RNG draw per collision decision */
static inline int evict_50_50(void) { return rng32() < 0x80000000u; }

/* ================================================================= */
/* Tables: split by protocol (DIFFERENT SIZES) */
/* ================================================================= */
static flow_entry_t table_tcp[TABLE_SIZE_TCP] = {0};
static flow_entry_t table_udp[TABLE_SIZE_UDP] = {0};

/* ================================================================= */
/* Timing-wheel (UDP-only) */
/* ================================================================= */
static int tw_head_udp[TW_SLOTS];
static time_t tw_now_sec = 0;
static int tw_now_slot = 0;
static int tw_initialised = 0;
static time_t last_pcap_sec = 0;
static volatile sig_atomic_t g_in_tw = 0;
static volatile sig_atomic_t g_tw_now_arg = 0;

/* ---------- stats ------------------------------------------------- */
static uint64_t st_flows_inserted = 0;
static uint64_t st_flows_matched = 0;
static uint64_t st_packets_tracked = 0;
static uint64_t st_collisions = 0;     /* collision EVENTS (after eligibility gating) */
static uint64_t st_battles = 0;
static uint64_t st_challenger_wins = 0;
static uint64_t st_incumbent_wins = 0;
static uint64_t st_udp_bloom_refused = 0; /* admission refused for new UDP attempts */
static uint64_t st_cap_flushes = 0;       /* flushed at FLOW_CAP */

/* ================================================================= */
/* Ground-truth per-flow packet counts + per-flow collision stats */
/* + timing fields (first/hit30/last timestamps) */
/* ================================================================= */
#define GT_SIZE (1u << 22) /* power-of-two */

typedef struct {
    int in_use;
    flow_key_t key;

    uint32_t pkt_count;     /* ground-truth count over entire PCAP */
    uint32_t collisions;    /* how many times this flow appears in collision events */
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

static inline void gt_count_packet_with_time(const flow_key_t *k, const struct timeval *tv) {
    gt_entry_t *e = gt_get_or_insert(k);
    if (!e) return;
    uint64_t t_us = tv_to_us(tv);
    e->pkt_count++;
    if (e->pkt_count == 1)  e->first_ts_us = t_us;
    if (e->pkt_count == 30) e->hit30_ts_us = t_us;
    e->last_ts_us = t_us;
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
/* Collision event logging */
/* ================================================================= */
typedef struct {
    flow_key_t winner;
    flow_key_t loser;
    uint8_t winner_was_incumbent;
    uint64_t ts_us;
} collision_rec_t;

static FILE *g_colbin = NULL;

static inline void ip_to_str(uint32_t ip, char out[INET_ADDRSTRLEN]) {
    inet_ntop(AF_INET, &ip, out, INET_ADDRSTRLEN);
}

static inline void log_collision_event(const struct timeval *tv,
                                       const flow_key_t *winner,
                                       const flow_key_t *loser,
                                       int winner_was_incumbent) {
    if (!g_colbin) return;
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
    if (!in) { perror("fopen random_chance_collisions.bin"); return; }

    FILE *out = fopen(csv_path, "w");
    if (!out) { perror("fopen random_chance_collisions.csv"); fclose(in); return; }

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
            r.ts_us,
            wip1, (unsigned)r.winner.port1, wip2, (unsigned)r.winner.port2,
            (r.winner.proto == IPPROTO_UDP ? "UDP" : "TCP"),
            lip1, (unsigned)r.loser.port1, lip2, (unsigned)r.loser.port2,
            (r.loser.proto == IPPROTO_UDP ? "UDP" : "TCP"),
            (unsigned)r.winner_was_incumbent,
            (unsigned)wp, (unsigned)lp,
            w_ge, l_ge);
    }

    fclose(out);
    fclose(in);
}

static void write_flow_collision_summary_csv(const char *csv_path) {
    FILE *out = fopen(csv_path, "w");
    if (!out) { perror("fopen random_chance_flow_collision_summary.csv"); return; }

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
            ip1, (unsigned)e->key.port1, ip2, (unsigned)e->key.port2,
            (e->key.proto == IPPROTO_UDP ? "UDP" : "TCP"),
            (unsigned)e->pkt_count, (e->pkt_count >= FLOW_CAP) ? 1 : 0,
            (unsigned)e->collisions, (unsigned)e->wins, (unsigned)e->losses,
            e->first_ts_us, e->hit30_ts_us, e->last_ts_us,
            dur_to_30, dur_30_to_last, dur_total);
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
/* Timing-wheel helpers */
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

    if (e->tw_prev != -1) base[e->tw_prev].tw_next = e->tw_next;
    else tw_head[slot] = e->tw_next;

    if (e->tw_next != -1) base[e->tw_next].tw_prev = e->tw_prev;

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
/* JSON encoding helpers */
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
/* Buffer / sender-thread logic */
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
/* helper functions */
static flow_key_t make_key(uint32_t s_ip, uint32_t d_ip, uint16_t s_pt, uint16_t d_pt, uint8_t proto) {
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
/* CSV logging */
static void write_to_csv(flow_entry_t *e) {
    if (e->count != FLOW_CAP) return;

    char ip_small[INET_ADDRSTRLEN], ip_large[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->key.ip1, ip_small, sizeof(ip_small));
    inet_ntop(AF_INET, &e->key.ip2, ip_large, sizeof(ip_large));

    char input_field[256];
    snprintf(input_field, sizeof(input_field), "%s%d%s%d%s",
             ip_small, e->key.port1, ip_large, e->key.port2, e->is_udp ? "UDP" : "TCP");

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

    const char *fname = e->is_udp ? "flow_output_timing_wheel_random_udp.csv"
                                  : "flow_output_timing_wheel_random_tcp.csv";

    FILE *f = fopen(fname, "a");
    if (!f) { perror("fopen"); exit(1); }
    fprintf(f, "%s,\"%s\"\n", input_field, feature_vector);
    fclose(f);
}

/* ================================================================= */
/* flow finalisation & output */
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
                ca, e->cli_port, sa, e->srv_port, e->is_udp ? "UDP" : "TCP", e->count, e->wins);
    }

    if (e->count >= FLOW_CAP) st_cap_flushes++;
    enqueue_flow(e);

    memset(e, 0, sizeof *e);
    e->tw_slot = e->tw_next = e->tw_prev = -1;
}

/* ================================================================= */
/* timing-wheel advance logic (UDP-only expiry) */
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
    if (now_sec <= tw_now_sec) { g_in_tw = 0; return; }

    time_t delta = now_sec - tw_now_sec;
    if (delta >= TW_SLOTS) {
        for (int s = 0; s < TW_SLOTS; ++s) expire_slot_list_udp(s);
        tw_now_sec = now_sec;
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
/* packet tracking (called per packet) */
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

/* Decide if we can admit a UDP flow (Bloom gate).
 * Returns 1 if allowed (definitely not seen -> inserts),
 * 0 if refused (probably seen). */
static inline int udp_admission_allowed(const flow_key_t *key) {
    int seen = udp_bloom_probably_seen_and_maybe_add(key, 1);
    if (seen) { st_udp_bloom_refused++; return 0; }
    return 1;
}

static void track_packet(const struct timeval *tv,
                         uint32_t sip, uint32_t dip,
                         uint16_t sport, uint16_t dport,
                         uint8_t proto,
                         int tcp_pure_syn,
                         uint16_t ip_len) {
    tw_advance(tv->tv_sec);

    flow_key_t key = make_key(sip, dip, sport, dport, proto);

    /* ground truth counts + timing */
    gt_count_packet_with_time(&key, tv);

    char kbuf[64];
    snprintf(kbuf, sizeof kbuf, "%08x%04x%08x%04x%02x",
             key.ip1, key.port1, key.ip2, key.port2, key.proto);

    uint32_t h = fnv1a_32(kbuf);

    /* UPDATED: protocol-specific table size & mask */
    flow_entry_t *base = (proto == IPPROTO_UDP) ? table_udp : table_tcp;
    uint32_t mask = (proto == IPPROTO_UDP) ? (TABLE_SIZE_UDP - 1u) : (TABLE_SIZE_TCP - 1u);
    uint32_t p = h & mask;

    int *tw_head = (proto == IPPROTO_UDP) ? tw_head_udp : NULL;
    flow_entry_t *m = &base[p];

    if (!m->in_use) {
        /* Admission gating for new entries */
        if (proto == IPPROTO_TCP && !tcp_pure_syn) return;
        if (proto == IPPROTO_UDP) {
            if (!udp_admission_allowed(&key)) return;
        }
        init_new_entry(m, key, sip, dip, sport, dport, proto);
        st_flows_inserted++;
    } else if (!compare_key(&m->key, &key)) {
        st_flows_matched++;
    } else {
        /* Challenger vs incumbent in this slot */
        /* Eligibility gating BEFORE counting/logging
           TCP: only pure SYN
           UDP: only if challenger passes Bloom admission */
        if (proto == IPPROTO_TCP) {
            if (!tcp_pure_syn) return;
        } else {
            if (!udp_admission_allowed(&key)) return;
        }

        st_collisions++;
        st_battles++;

        /* RANDOM 50/50 eviction */
        if (evict_50_50()) {
            /* Challenger wins */
            st_challenger_wins++;
            log_collision_event(tv, &key, &m->key, 0);

            if (proto == IPPROTO_UDP && tw_head != NULL) {
                tw_remove_generic(base, tw_head, (int)p);
            }
            init_new_entry(m, key, sip, dip, sport, dport, proto);
            st_flows_inserted++;
        } else {
            /* Incumbent wins */
            st_incumbent_wins++;
            m->wins++;
            log_collision_event(tv, &m->key, &key, 1);
            return;
        }
    }

    /* Track packet into the table entry */
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
        dump_and_clear(base, m, tw_head);
    }
}

/* ================================================================= */
/* parse Ethernet/IP/TCP/UDP & call tracker */
static int parse_and_track(const struct pcap_pkthdr *h, const u_char *pkt) {
    const struct ether_header *eth = (const struct ether_header *)pkt;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;

    const struct ip *ip = (const struct ip *)(pkt + sizeof *eth);
    uint8_t proto = ip->ip_p;

    uint32_t sip = ip->ip_src.s_addr, dip = ip->ip_dst.s_addr;
    uint16_t sport = 0, dport = 0;
    int pure_syn = 0;

    int ip_hl = ip->ip_hl * 4;

    if (proto == IPPROTO_TCP) {
        const struct tcphdr *th = (const struct tcphdr *)(pkt + sizeof *eth + ip_hl);
        sport = ntohs(th->th_sport);
        dport = ntohs(th->th_dport);
        /* PURE SYN only */
        pure_syn = (th->th_flags == TH_SYN);
    } else if (proto == IPPROTO_UDP) {
        const struct udphdr *uh = (const struct udphdr *)(pkt + sizeof *eth + ip_hl);
        sport = ntohs(uh->uh_sport);
        dport = ntohs(uh->uh_dport);
    } else {
        return 0;
    }

    last_pcap_sec = h->ts.tv_sec;
    track_packet(&h->ts, sip, dip, sport, dport, proto, pure_syn, ntohs(ip->ip_len));
    return 1;
}

/* ================================================================= */
/* main */
int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s file.pcap [seed]\n", argv[0]);
        return 1;
    }

    uint32_t seed = 123456789u;
    if (argc == 3) seed = (uint32_t)strtoul(argv[2], NULL, 10);

    rng_seed(seed);
    fprintf(stderr, "RNG seed=%u\n", seed);
    fprintf(stderr, "TABLE_SIZE_TCP=%u TABLE_SIZE_UDP=%u\n",
            (unsigned)TABLE_SIZE_TCP, (unsigned)TABLE_SIZE_UDP);

    udp_bloom_clear();
    for (int i = 0; i < TW_SLOTS; ++i) tw_head_udp[i] = -1;

    memset(gt_tab, 0, sizeof(gt_tab));

    g_colbin = fopen("random_chance_collisions.bin", "wb");
    if (!g_colbin) { perror("fopen random_chance_collisions.bin"); return 1; }

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

    /* UPDATED: flush each table with its own size */
    for (uint32_t i = 0; i < TABLE_SIZE_TCP; ++i) {
        if (table_tcp[i].in_use) dump_and_clear(table_tcp, &table_tcp[i], NULL);
    }
    for (uint32_t i = 0; i < TABLE_SIZE_UDP; ++i) {
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
        "stats: inserted=%" PRIu64 " matched=%" PRIu64 " pkts_tracked=%" PRIu64
        " collisions=%" PRIu64 " battles=%" PRIu64 " challenger_wins=%" PRIu64
        " incumbent_wins=%" PRIu64 " udp_bloom_refused=%" PRIu64 " cap_flushes=%" PRIu64 "\n",
        st_flows_inserted, st_flows_matched, st_packets_tracked,
        st_collisions, st_battles, st_challenger_wins,
        st_incumbent_wins, st_udp_bloom_refused, st_cap_flushes);

    fclose(g_colbin);
    g_colbin = NULL;

    write_collisions_csv_from_bin("random_chance_collisions.bin", "random_chance_collisions.csv");
    write_flow_collision_summary_csv("random_chance_flow_collision_summary.csv");
    return 0;
}
