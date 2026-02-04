// flow_pkt_counts_dir.c
// Walk a directory (non-recursive), open each .pcap/.pcapng, and aggregate packet counts per
// bidirectional 5-tuple flow (A<->B combined). Output a single CSV.
//
// Build: gcc -O3 -march=native -Wall -Wextra -o flow_pkt_counts_dir flow_pkt_counts_dir.c -lpcap
// Run:   ./flow_pkt_counts_dir /path/to/pcaps output.csv

#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#pragma pack(push, 1)
struct eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
};

struct vlan_hdr {
    uint16_t tci;
    uint16_t ethertype;
};

struct ipv4_hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off_res;
    uint8_t  flags;
    uint16_t win;
    uint16_t csum;
    uint16_t urp;
};

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t csum;
};
#pragma pack(pop)

typedef struct {
    uint32_t ip_a;
    uint32_t ip_b;
    uint16_t port_a;
    uint16_t port_b;
    uint8_t  proto;
    uint8_t  pad[3];
} flow_key_t;

typedef struct flow_entry {
    flow_key_t key;
    uint64_t   pkts;
    struct flow_entry *next;
} flow_entry_t;

typedef struct {
    flow_entry_t **buckets;
    size_t nbuckets;
    size_t nentries;
} flow_table_t;

static inline uint64_t rotl64(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
static inline uint64_t mix64(uint64_t x) {
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33; return x;
}
static inline uint64_t flow_hash(const flow_key_t *k) {
    uint64_t a = ((uint64_t)k->ip_a << 32) | (uint64_t)k->ip_b;
    uint64_t b = ((uint64_t)k->port_a << 48) | ((uint64_t)k->port_b << 32) | ((uint64_t)k->proto << 24);
    return mix64(a ^ rotl64(b, 17));
}
static inline int flow_eq(const flow_key_t *x, const flow_key_t *y) {
    return memcmp(x, y, sizeof(flow_key_t)) == 0;
}

static void table_init(flow_table_t *t, size_t nbuckets_pow2) {
    t->nbuckets = nbuckets_pow2;
    t->nentries = 0;
    t->buckets = (flow_entry_t**)calloc(t->nbuckets, sizeof(flow_entry_t*));
    if (!t->buckets) { perror("calloc"); exit(1); }
}
static void table_free(flow_table_t *t) {
    if (!t || !t->buckets) return;
    for (size_t i = 0; i < t->nbuckets; i++) {
        flow_entry_t *e = t->buckets[i];
        while (e) { flow_entry_t *n = e->next; free(e); e = n; }
    }
    free(t->buckets);
    t->buckets = NULL;
}
static void table_grow(flow_table_t *t) {
    size_t newb = t->nbuckets * 2;
    flow_entry_t **nb = (flow_entry_t**)calloc(newb, sizeof(flow_entry_t*));
    if (!nb) return;
    for (size_t i = 0; i < t->nbuckets; i++) {
        flow_entry_t *e = t->buckets[i];
        while (e) {
            flow_entry_t *n = e->next;
            size_t idx = (size_t)(flow_hash(&e->key) & (newb - 1));
            e->next = nb[idx];
            nb[idx] = e;
            e = n;
        }
    }
    free(t->buckets);
    t->buckets = nb;
    t->nbuckets = newb;
}
static flow_entry_t* table_get_or_insert(flow_table_t *t, const flow_key_t *key) {
    if (unlikely(t->nentries > (t->nbuckets * 3) / 2)) table_grow(t);
    size_t idx = (size_t)(flow_hash(key) & (t->nbuckets - 1));
    flow_entry_t *e = t->buckets[idx];
    while (e) { if (flow_eq(&e->key, key)) return e; e = e->next; }
    flow_entry_t *ne = (flow_entry_t*)calloc(1, sizeof(flow_entry_t));
    if (!ne) { perror("calloc"); exit(1); }
    ne->key = *key;
    ne->pkts = 0;
    ne->next = t->buckets[idx];
    t->buckets[idx] = ne;
    t->nentries++;
    return ne;
}

static inline void canonicalize(flow_key_t *k) {
    uint32_t ip1 = k->ip_a, ip2 = k->ip_b;
    uint16_t p1  = k->port_a, p2 = k->port_b;
    int swap = 0;
    if (ip1 > ip2) swap = 1;
    else if (ip1 == ip2 && p1 > p2) swap = 1;
    if (swap) {
        k->ip_a = ip2; k->ip_b = ip1;
        k->port_a = p2; k->port_b = p1;
    }
}

static inline int parse_eth_ipv4_5tuple(const uint8_t *pkt, uint32_t caplen, flow_key_t *out_key) {
    if (caplen < sizeof(struct eth_hdr)) return 0;
    const struct eth_hdr *eth = (const struct eth_hdr*)pkt;
    uint16_t et = ntohs(eth->ethertype);
    uint32_t off = sizeof(struct eth_hdr);

    if (et == 0x8100) { // VLAN
        if (caplen < off + sizeof(struct vlan_hdr)) return 0;
        const struct vlan_hdr *vh = (const struct vlan_hdr*)(pkt + off);
        et = ntohs(vh->ethertype);
        off += sizeof(struct vlan_hdr);
    }
    if (et != 0x0800) return 0; // IPv4 only

    if (caplen < off + sizeof(struct ipv4_hdr)) return 0;
    const struct ipv4_hdr *ip = (const struct ipv4_hdr*)(pkt + off);
    uint8_t ver = ip->ver_ihl >> 4;
    if (ver != 4) return 0;
    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ihl < 20) return 0;
    if (caplen < off + ihl) return 0;

    uint8_t proto = ip->proto;
    uint32_t ip_off = off + ihl;

    uint16_t sport = 0, dport = 0;
    if (proto == 6) { // TCP
        if (caplen < ip_off + sizeof(struct tcp_hdr)) return 0;
        const struct tcp_hdr *tcp = (const struct tcp_hdr*)(pkt + ip_off);
        sport = tcp->sport;
        dport = tcp->dport;
    } else if (proto == 17) { // UDP
        if (caplen < ip_off + sizeof(struct udp_hdr)) return 0;
        const struct udp_hdr *udp = (const struct udp_hdr*)(pkt + ip_off);
        sport = udp->sport;
        dport = udp->dport;
    } else {
        sport = 0; dport = 0;
    }

    memset(out_key, 0, sizeof(*out_key));
    out_key->ip_a = ip->saddr;
    out_key->ip_b = ip->daddr;
    out_key->port_a = sport;
    out_key->port_b = dport;
    out_key->proto = proto;

    canonicalize(out_key);
    return 1;
}

static int has_suffix_ci(const char *s, const char *suf) {
    size_t n = strlen(s), m = strlen(suf);
    if (m > n) return 0;
    const char *p = s + (n - m);
    for (size_t i = 0; i < m; i++) {
        char a = p[i], b = suf[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

static int is_regular_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

static void process_one_pcap(flow_table_t *tab, const char *path,
                             uint64_t *total_pkts, uint64_t *parsed_pkts, uint64_t *pcap_files) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_open_offline(path, errbuf);
    if (!pc) {
        fprintf(stderr, "WARN: cannot open %s: %s\n", path, errbuf);
        return;
    }

    int dlt = pcap_datalink(pc);
    if (dlt != DLT_EN10MB) {
        fprintf(stderr, "WARN: %s unsupported datalink %d (need Ethernet)\n", path, dlt);
        pcap_close(pc);
        return;
    }

    struct pcap_pkthdr *hdr;
    const uint8_t *pkt;
    int rc;

    (*pcap_files)++;

    while ((rc = pcap_next_ex(pc, &hdr, &pkt)) == 1) {
        (*total_pkts)++;
        flow_key_t k;
        if (parse_eth_ipv4_5tuple(pkt, hdr->caplen, &k)) {
            flow_entry_t *e = table_get_or_insert(tab, &k);
            e->pkts++;
            (*parsed_pkts)++;
        }
    }
    if (rc == -1) {
        fprintf(stderr, "WARN: read error %s: %s\n", path, pcap_geterr(pc));
    }

    pcap_close(pc);
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <pcap_dir> <output.csv>\n", prog);
    fprintf(stderr, "Reads all .pcap/.pcapng files in directory (non-recursive) and aggregates flow packet counts.\n");
}

int main(int argc, char **argv) {
    if (argc != 3) { usage(argv[0]); return 2; }
    const char *dirpath = argv[1];
    const char *outpath = argv[2];

    DIR *d = opendir(dirpath);
    if (!d) {
        fprintf(stderr, "opendir(%s) failed: %s\n", dirpath, strerror(errno));
        return 1;
    }

    // Start hash table: adjust based on expected unique flows.
    // 2^20 buckets (~1M) is a good default for big traces.
    flow_table_t tab;
    table_init(&tab, 1u << 20);

    uint64_t total_pkts = 0, parsed_pkts = 0, pcap_files = 0;

    struct dirent *de;
    char full[PATH_MAX];

    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        if (name[0] == '.') continue;

        if (!(has_suffix_ci(name, ".pcap") || has_suffix_ci(name, ".pcapng"))) continue;

        // Build full path
        int n = snprintf(full, sizeof(full), "%s/%s", dirpath, name);
        if (n <= 0 || (size_t)n >= sizeof(full)) {
            fprintf(stderr, "WARN: path too long, skipping %s\n", name);
            continue;
        }

        if (!is_regular_file(full)) continue;

        fprintf(stderr, "Processing %s\n", full);
        process_one_pcap(&tab, full, &total_pkts, &parsed_pkts, &pcap_files);
    }

    closedir(d);

    FILE *out = fopen(outpath, "w");
    if (!out) {
        perror("fopen");
        table_free(&tab);
        return 1;
    }

    fprintf(out, "src_ip,src_port,dst_ip,dst_port,proto,packets\n");

    char ipbuf_a[INET_ADDRSTRLEN], ipbuf_b[INET_ADDRSTRLEN];
    for (size_t i = 0; i < tab.nbuckets; i++) {
        for (flow_entry_t *e = tab.buckets[i]; e; e = e->next) {
            struct in_addr ia, ib;
            ia.s_addr = e->key.ip_a;
            ib.s_addr = e->key.ip_b;

            const char *sa = inet_ntop(AF_INET, &ia, ipbuf_a, sizeof(ipbuf_a));
            const char *sb = inet_ntop(AF_INET, &ib, ipbuf_b, sizeof(ipbuf_b));
            if (!sa) sa = "0.0.0.0";
            if (!sb) sb = "0.0.0.0";

            uint16_t pa = ntohs(e->key.port_a);
            uint16_t pb = ntohs(e->key.port_b);

            fprintf(out, "%s,%u,%s,%u,%u,%llu\n",
                    sa, (unsigned)pa, sb, (unsigned)pb, (unsigned)e->key.proto,
                    (unsigned long long)e->pkts);
        }
    }
    fclose(out);

    fprintf(stderr, "PCAP files: %llu | Read packets: %llu | Parsed IPv4: %llu | Unique flows: %zu\n",
            (unsigned long long)pcap_files,
            (unsigned long long)total_pkts,
            (unsigned long long)parsed_pkts,
            tab.nentries);

    table_free(&tab);
    return 0;
}
