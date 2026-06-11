// XDP Layer-4 drop program. BTF `.maps` style so the object loads in aya.
// Compiled by build.rs:
//   clang -O2 -g -Wall -target bpfel -c src/bpf/xdp.c -o $OUT_DIR/xdp.o

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define bpf_htons(x) ((__u16)(__builtin_constant_p(x) ? \
    (((__u16)(x) & 0xffU) << 8) | (((__u16)(x) & 0xff00U) >> 8) : \
    __builtin_bswap16(x)))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
// bpf_ktime_get_ns — helper id 5, available in XDP context since kernel 4.1.
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;

// ── Maps ─────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, __u8);
} blocklist SEC(".maps");

struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct conn_key);
    __type(value, __u8);
} allowed_flows SEC(".maps");

// Per-packet statistics broken down by drop reason.
// `allowed` + `blocked` = total packets seen (modulo accounting on PASS for
// non-service traffic); `drop_*` fields sum to `blocked`.
// IMPORTANT: field order must stay byte-identical to BpfStats in xdp.rs.
struct stats {
    __u64 allowed;
    __u64 blocked;
    __u64 drop_blocklist;      // source IP on the XDP blocklist
    __u64 drop_udp;            // UDP flood to service port (non-amplification)
    __u64 drop_tcp_malformed;  // truncated / malformed TCP / bad IP header length
    __u64 drop_http_invalid;   // :80 payload that is not a valid HTTP request line
    __u64 drop_tls_invalid;    // :443 payload that is not a TLS ClientHello
    __u64 drop_icmp;           // ICMP echo flood (type 8)
    __u64 drop_bad_flags;      // NULL / Xmas / SYN+FIN / RST+SYN TCP flags
    __u64 drop_fragment;       // IP fragmentation (MF or non-zero offset)
    __u64 drop_amplify;        // UDP from known reflection/amplification source ports
    __u64 drop_syn_flood;      // SYN rate-limit exceeded for this source IP
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} xdp_stats SEC(".maps");

// Drop reason codes (must match the drop_* field order above starting at 0).
#define DROP_BLOCKLIST      0
#define DROP_UDP            1
#define DROP_TCP_MALFORMED  2
#define DROP_HTTP_INVALID   3
#define DROP_TLS_INVALID    4
#define DROP_ICMP           5
#define DROP_BAD_FLAGS      6
#define DROP_FRAGMENT       7
#define DROP_AMPLIFY        8
#define DROP_SYN_FLOOD      9

// ── SYN rate-limiting map ─────────────────────────────────────────────────────
// Tracks SYN count per source IP within a 1-second window. When a single IP
// exceeds SYN_MAX_PER_SEC pure SYNs/sec its SYNs are dropped as a flood.
struct syn_entry {
    __u32 count;
    __u32 _pad;             // explicit pad so window_start_ns is 8-byte aligned
    __u64 window_start_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);             // src_ip
    __type(value, struct syn_entry);
} syn_rates SEC(".maps");

#define SYN_WINDOW_NS    1000000000ULL  // 1 second in nanoseconds
#define SYN_MAX_PER_SEC  100            // SYN/s per IP before dropping

// ── Attack-payload fingerprinting map ────────────────────────────────────────
// FNV-1a hash of the first FP_SAMPLE_LEN bytes of a dropped payload → count
// and raw bytes. Floods replay the same payload so the top-count entry is the
// attack signature. LRU prevents low-count junk from evicting flood entries.
// IMPORTANT: struct layout must stay byte-identical to BpfFingerprint in xdp.rs.
#define FP_SAMPLE_LEN 16

struct fingerprint {
    __u64 count;
    __u32 len;
    __u8  bytes[FP_SAMPLE_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct fingerprint);
} fingerprints SEC(".maps");

// ── Stat helpers ──────────────────────────────────────────────────────────────

static __always_inline void count_allowed(struct stats *st) {
    if (st) __sync_fetch_and_add(&st->allowed, 1);
}

static __always_inline void count_drop(struct stats *st, int reason) {
    if (!st) return;
    __sync_fetch_and_add(&st->blocked, 1);
    switch (reason) {
        case DROP_BLOCKLIST:     __sync_fetch_and_add(&st->drop_blocklist, 1);     break;
        case DROP_UDP:           __sync_fetch_and_add(&st->drop_udp, 1);           break;
        case DROP_TCP_MALFORMED: __sync_fetch_and_add(&st->drop_tcp_malformed, 1); break;
        case DROP_HTTP_INVALID:  __sync_fetch_and_add(&st->drop_http_invalid, 1);  break;
        case DROP_TLS_INVALID:   __sync_fetch_and_add(&st->drop_tls_invalid, 1);   break;
        case DROP_ICMP:          __sync_fetch_and_add(&st->drop_icmp, 1);          break;
        case DROP_BAD_FLAGS:     __sync_fetch_and_add(&st->drop_bad_flags, 1);     break;
        case DROP_FRAGMENT:      __sync_fetch_and_add(&st->drop_fragment, 1);      break;
        case DROP_AMPLIFY:       __sync_fetch_and_add(&st->drop_amplify, 1);       break;
        case DROP_SYN_FLOOD:     __sync_fetch_and_add(&st->drop_syn_flood, 1);     break;
    }
}

// ── Fingerprint helper ────────────────────────────────────────────────────────

static __always_inline void record_fingerprint(unsigned char *payload, void *data_end) {
    struct fingerprint fp = {};
    __u32 hash = 2166136261u; // FNV-1a 32-bit offset basis
    __u32 n = 0;

#pragma unroll
    for (int i = 0; i < FP_SAMPLE_LEN; i++) {
        if ((void *)(payload + i + 1) > data_end) break;
        __u8 b = payload[i];
        fp.bytes[i] = b;
        hash = (hash ^ (__u32)b) * 16777619u;
        n++;
    }

    if (n == 0) return;

    struct fingerprint *existing = bpf_map_lookup_elem(&fingerprints, &hash);
    if (existing) {
        __sync_fetch_and_add(&existing->count, 1);
    } else {
        fp.count = 1;
        fp.len = n;
        bpf_map_update_elem(&fingerprints, &hash, &fp, BPF_ANY);
    }
}

// ── Protocol helpers ──────────────────────────────────────────────────────────

static __always_inline int is_service_port(__u16 port) {
    return port == bpf_htons(80) || port == bpf_htons(443);
}

// UDP source ports used by popular reflection/amplification attack vectors.
// When an attacker spoofs the victim's IP and queries one of these services,
// the (often much larger) response is delivered to the victim from this port.
static __always_inline int is_amplification_src_port(__u16 port) {
    return port == bpf_htons(53)    // DNS
        || port == bpf_htons(123)   // NTP
        || port == bpf_htons(1900)  // SSDP / UPnP
        || port == bpf_htons(11211) // Memcached
        || port == bpf_htons(5353)  // mDNS
        || port == bpf_htons(389)   // LDAP / CLDAP
        || port == bpf_htons(19)    // Chargen
        || port == bpf_htons(111)   // RPC / portmap
        || port == bpf_htons(520)   // RIPv1
        || port == bpf_htons(161)   // SNMP
        || port == bpf_htons(1194)  // OpenVPN (used in amplification)
        || port == bpf_htons(3702); // WS-Discovery (Windows amplification vector)
}

// Per-source-IP SYN rate limiter. Returns 1 (and records the drop) when the
// source has exceeded SYN_MAX_PER_SEC pure SYNs within the current 1-second
// window; returns 0 and passes otherwise.
static __always_inline int check_syn_rate(__u32 src_ip, struct stats *st) {
    __u64 now = bpf_ktime_get_ns();

    struct syn_entry *entry = bpf_map_lookup_elem(&syn_rates, &src_ip);
    if (entry) {
        if (now - entry->window_start_ns < SYN_WINDOW_NS) {
            entry->count++;
            if (entry->count > SYN_MAX_PER_SEC) {
                count_drop(st, DROP_SYN_FLOOD);
                return 1;
            }
        } else {
            // Window expired — start a new one.
            entry->window_start_ns = now;
            entry->count = 1;
        }
    } else {
        struct syn_entry new_entry = {};
        new_entry.count = 1;
        new_entry.window_start_ns = now;
        bpf_map_update_elem(&syn_rates, &src_ip, &new_entry, BPF_ANY);
    }
    return 0;
}

static __always_inline int is_http_request(unsigned char *payload, void *data_end) {
    if ((void *)(payload + 4) <= data_end &&
        payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ')
        return 1;
    if ((void *)(payload + 5) <= data_end &&
        payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T' && payload[4] == ' ')
        return 1;
    if ((void *)(payload + 5) <= data_end &&
        payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D' && payload[4] == ' ')
        return 1;
    if ((void *)(payload + 4) <= data_end &&
        payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ')
        return 1;
    if ((void *)(payload + 7) <= data_end &&
        payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E' &&
        payload[4] == 'T' && payload[5] == 'E' && payload[6] == ' ')
        return 1;
    if ((void *)(payload + 8) <= data_end &&
        payload[0] == 'O' && payload[1] == 'P' && payload[2] == 'T' && payload[3] == 'I' &&
        payload[4] == 'O' && payload[5] == 'N' && payload[6] == 'S' && payload[7] == ' ')
        return 1;
    if ((void *)(payload + 6) <= data_end &&
        payload[0] == 'P' && payload[1] == 'A' && payload[2] == 'T' && payload[3] == 'C' &&
        payload[4] == 'H' && payload[5] == ' ')
        return 1;
    if ((void *)(payload + 8) <= data_end &&
        payload[0] == 'C' && payload[1] == 'O' && payload[2] == 'N' && payload[3] == 'N' &&
        payload[4] == 'E' && payload[5] == 'C' && payload[6] == 'T' && payload[7] == ' ')
        return 1;
    if ((void *)(payload + 6) <= data_end &&
        payload[0] == 'T' && payload[1] == 'R' && payload[2] == 'A' && payload[3] == 'C' &&
        payload[4] == 'E' && payload[5] == ' ')
        return 1;
    if ((void *)(payload + 24) <= data_end &&
        payload[0] == 'P' && payload[1] == 'R' && payload[2] == 'I' && payload[3] == ' ' &&
        payload[4] == '*' && payload[5] == ' ' && payload[6] == 'H' && payload[7] == 'T' &&
        payload[8] == 'T' && payload[9] == 'P' && payload[10] == '/' && payload[11] == '2' &&
        payload[12] == '.' && payload[13] == '0' && payload[14] == '\r' && payload[15] == '\n' &&
        payload[16] == '\r' && payload[17] == '\n' && payload[18] == 'S' && payload[19] == 'M' &&
        payload[20] == '\r' && payload[21] == '\n' && payload[22] == '\r' && payload[23] == '\n')
        return 1;
    return 0;
}

static __always_inline int is_tls_client_hello(unsigned char *payload, void *data_end) {
    if ((void *)(payload + 6) > data_end) return 0;
    if (payload[0] != 0x16) return 0;
    if (payload[1] != 0x03) return 0;
    if (payload[2] < 0x01 || payload[2] > 0x04) return 0;
    if (payload[5] != 0x01) return 0;
    return 1;
}

// ── Main XDP program ──────────────────────────────────────────────────────────

SEC("xdp")
int xdp_drop_func(struct xdp_md *ctx) {
    __u32 stats_key = 0;
    struct stats *st = bpf_map_lookup_elem(&xdp_stats, &stats_key);

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // ── Ethernet ─────────────────────────────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) { count_allowed(st); return XDP_PASS; }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) { count_allowed(st); return XDP_PASS; }

    // ── IPv4 header ───────────────────────────────────────────────────────────
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) { count_allowed(st); return XDP_PASS; }

    // Blocklist fast-path — known-bad source IPs are rejected first.
    __u32 src_ip = ip->saddr;
    if (bpf_map_lookup_elem(&blocklist, &src_ip)) {
        count_drop(st, DROP_BLOCKLIST);
        return XDP_DROP;
    }

    // Validate IP header length.
    __u32 ip_hdr_len = (__u32)ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip)) {
        count_drop(st, DROP_TCP_MALFORMED);
        return XDP_DROP;
    }

    // IP fragmentation: MF bit or non-zero fragment offset.
    // Legitimate HTTP/HTTPS traffic is virtually never IP-fragmented; this is a
    // classic attack vector (frag flood, overlapping-fragment evasion).
    // Mask: bit 13 (MF) + bits 0-12 (fragment offset) = 0x3FFF in host order.
    if (ip->frag_off & bpf_htons(0x3FFF)) {
        count_drop(st, DROP_FRAGMENT);
        return XDP_DROP;
    }

    // ── ICMP ─────────────────────────────────────────────────────────────────
    if (ip->protocol == IPPROTO_ICMP) {
        unsigned char *icmp = (unsigned char *)(data + sizeof(*eth) + ip_hdr_len);
        if ((void *)(icmp + 1) > data_end) {
            count_drop(st, DROP_ICMP);
            return XDP_DROP;
        }
        // Drop echo requests (type 8). Echo replies, unreachables, TTL exceeded,
        // etc. are left alone because they're needed for routing / PMTUD.
        if (icmp[0] == 8) {
            record_fingerprint(icmp + 4, data_end); // after 4-byte ICMP header
            count_drop(st, DROP_ICMP);
            return XDP_DROP;
        }
        count_allowed(st);
        return XDP_PASS;
    }

    // ── UDP ───────────────────────────────────────────────────────────────────
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + sizeof(*eth) + ip_hdr_len;
        if ((void *)(udp + 1) > data_end) {
            count_drop(st, DROP_UDP);
            return XDP_DROP;
        }

        // Reflection/amplification: attacker spoofs victim's IP and queries a
        // reflector; the amplified response arrives from the reflector's service
        // port. Drop regardless of destination port — these responses are never
        // legitimate inbound traffic on a web server.
        if (is_amplification_src_port(udp->source)) {
            record_fingerprint((unsigned char *)(udp + 1), data_end);
            count_drop(st, DROP_AMPLIFY);
            return XDP_DROP;
        }

        // Generic UDP flood: we serve nothing over UDP on service ports.
        if (is_service_port(udp->dest)) {
            record_fingerprint((unsigned char *)(udp + 1), data_end);
            count_drop(st, DROP_UDP);
            return XDP_DROP;
        }

        count_allowed(st);
        return XDP_PASS;
    }

    // ── TCP ───────────────────────────────────────────────────────────────────
    if (ip->protocol != IPPROTO_TCP) { count_allowed(st); return XDP_PASS; }

    struct tcphdr *tcp = data + sizeof(*eth) + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end) {
        count_drop(st, DROP_TCP_MALFORMED);
        return XDP_DROP;
    }

    __u32 tcp_hdr_len = (__u32)tcp->doff * 4;
    if (tcp_hdr_len < sizeof(*tcp)) {
        count_drop(st, DROP_TCP_MALFORMED);
        return XDP_DROP;
    }

    unsigned char *payload = (unsigned char *)tcp + tcp_hdr_len;
    if ((void *)payload > data_end) {
        count_drop(st, DROP_TCP_MALFORMED);
        return XDP_DROP;
    }

    // Malformed TCP flag combinations used in scan/flood attacks:
    //   NULL scan  — no flags at all
    //   Xmas tree  — SYN+FIN+PSH+URG all set (0x2B)
    //   SYN+FIN    — contradictory, never valid
    //   RST+SYN    — contradictory, never valid
    {
        __u8 f = (tcp->fin ? 0x01u : 0)
               | (tcp->syn ? 0x02u : 0)
               | (tcp->rst ? 0x04u : 0)
               | (tcp->psh ? 0x08u : 0)
               | (tcp->ack ? 0x10u : 0)
               | (tcp->urg ? 0x20u : 0);
        if (f == 0                   // NULL
            || (f & 0x03u) == 0x03u  // SYN+FIN
            || (f & 0x06u) == 0x06u  // RST+SYN
            || (f & 0x2Bu) == 0x2Bu) // Xmas (SYN+FIN+PSH+URG)
        {
            count_drop(st, DROP_BAD_FLAGS);
            return XDP_DROP;
        }
    }

    // Only service ports from here on.
    if (!is_service_port(tcp->dest)) { count_allowed(st); return XDP_PASS; }

    // Flow tracking: established / allowed flows bypass further validation.
    struct conn_key key = {
        .src_ip   = ip->saddr,
        .dst_ip   = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    if (bpf_map_lookup_elem(&allowed_flows, &key)) {
        if (tcp->fin || tcp->rst)
            bpf_map_delete_elem(&allowed_flows, &key);
        count_allowed(st);
        return XDP_PASS;
    }

    // No payload: SYN (new connection), ACK, keepalive, etc.
    if ((void *)payload == data_end) {
        // Rate-limit pure SYNs (SYN without ACK = connection initiation).
        // SYN+ACK comes from the server side, not from clients.
        if (tcp->syn && !tcp->ack) {
            if (check_syn_rate(src_ip, st))
                return XDP_DROP;
        }
        count_allowed(st);
        return XDP_PASS;
    }

    // First data packet: must open with a valid HTTP request or TLS ClientHello.
    if (tcp->dest == bpf_htons(80) && is_http_request(payload, data_end)) {
        __u8 v = 1;
        bpf_map_update_elem(&allowed_flows, &key, &v, BPF_ANY);
        count_allowed(st);
        return XDP_PASS;
    }
    if (tcp->dest == bpf_htons(443) && is_tls_client_hello(payload, data_end)) {
        __u8 v = 1;
        bpf_map_update_elem(&allowed_flows, &key, &v, BPF_ANY);
        count_allowed(st);
        return XDP_PASS;
    }

    // Payload-bearing junk on a service port — capture signature and drop.
    record_fingerprint(payload, data_end);
    if (tcp->dest == bpf_htons(80))
        count_drop(st, DROP_HTTP_INVALID);
    else
        count_drop(st, DROP_TLS_INVALID);
    return XDP_DROP;
}

char _license[] SEC("license") = "Dual MIT/GPL";
