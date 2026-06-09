// XDP Layer-4 drop program. Logic identical to the Go build's xdp.c, but maps
// are declared in the modern BTF `.maps` style (no legacy bpf_map_def) so the
// object can be loaded by aya. Compiled by build.rs with:
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

// BTF map definition macros (the standard trick to avoid depending on
// <bpf/bpf_helpers.h>).
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Helper for byte swapping if needed (e.g. __builtin_bswap16)
#define bpf_htons(x) ((__u16)(__builtin_constant_p(x) ? \
    (((__u16)(x) & 0xffU) << 8) | (((__u16)(x) & 0xff00U) >> 8) : \
    __builtin_bswap16(x)))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;

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

// Per-packet statistics. `allowed`/`blocked` are the running totals (unchanged
// from the original program); the `drop_*` fields break the blocked total down
// by *why* the packet was dropped, so userspace can classify the attack type.
struct stats {
    __u64 allowed;
    __u64 blocked;
    __u64 drop_blocklist;     // source IP is on the XDP blocklist
    __u64 drop_udp;           // UDP to a service port (UDP flood) / malformed UDP
    __u64 drop_tcp_malformed; // truncated / malformed TCP segment
    __u64 drop_http_invalid;  // :80 payload that is not a valid HTTP request line
    __u64 drop_tls_invalid;   // :443 payload that is not a TLS ClientHello
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} xdp_stats SEC(".maps");

// Drop reason codes (kept in sync with the per-reason fields above).
#define DROP_BLOCKLIST     0
#define DROP_UDP           1
#define DROP_TCP_MALFORMED 2
#define DROP_HTTP_INVALID  3
#define DROP_TLS_INVALID   4

// ── Attack fingerprinting ────────────────────────────────────────────────────
// A "fingerprint" is a hash of the first FP_SAMPLE_LEN bytes of a dropped
// packet's payload, together with a copy of those bytes and an occurrence
// counter. Floods tend to replay an identical (or near-identical) payload, so
// the highest-count fingerprint is the signature of the current attack. The map
// is an LRU hash so one-off junk can't exhaust it during a real flood.
#define FP_SAMPLE_LEN 16

struct fingerprint {
    __u64 count;
    __u32 len;                 // number of valid bytes captured (<= FP_SAMPLE_LEN)
    __u8  bytes[FP_SAMPLE_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct fingerprint);
} fingerprints SEC(".maps");

static __always_inline void count_allowed(struct stats *st) {
    if (st) __sync_fetch_and_add(&st->allowed, 1);
}

// Increment the total blocked counter plus the per-reason breakdown.
static __always_inline void count_drop(struct stats *st, int reason) {
    if (!st) return;
    __sync_fetch_and_add(&st->blocked, 1);
    switch (reason) {
        case DROP_BLOCKLIST:     __sync_fetch_and_add(&st->drop_blocklist, 1);     break;
        case DROP_UDP:           __sync_fetch_and_add(&st->drop_udp, 1);           break;
        case DROP_TCP_MALFORMED: __sync_fetch_and_add(&st->drop_tcp_malformed, 1); break;
        case DROP_HTTP_INVALID:  __sync_fetch_and_add(&st->drop_http_invalid, 1);  break;
        case DROP_TLS_INVALID:   __sync_fetch_and_add(&st->drop_tls_invalid, 1);   break;
    }
}

// Sample the first FP_SAMPLE_LEN bytes of a dropped payload, FNV-1a hash them,
// and bump (or insert) the matching fingerprint entry. Safe to call even when
// no payload is present — the bounds check breaks out and nothing is recorded.
static __always_inline void record_fingerprint(unsigned char *payload, void *data_end) {
    struct fingerprint fp = {};
    __u32 hash = 2166136261u; // FNV-1a 32-bit offset basis
    __u32 n = 0;

#pragma unroll
    for (int i = 0; i < FP_SAMPLE_LEN; i++) {
        if ((void *)(payload + i + 1) > data_end)
            break;
        __u8 b = payload[i];
        fp.bytes[i] = b;
        hash = (hash ^ (__u32)b) * 16777619u; // FNV-1a prime
        n++;
    }

    if (n == 0)
        return;

    struct fingerprint *existing = bpf_map_lookup_elem(&fingerprints, &hash);
    if (existing) {
        __sync_fetch_and_add(&existing->count, 1);
    } else {
        fp.count = 1;
        fp.len = n;
        bpf_map_update_elem(&fingerprints, &hash, &fp, BPF_ANY);
    }
}

static __always_inline int is_http_request(unsigned char *payload, void *data_end) {
    if ((void *)(payload + 4) <= data_end &&
        payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') {
        return 1;
    }

    if ((void *)(payload + 5) <= data_end &&
        payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T' && payload[4] == ' ') {
        return 1;
    }

    if ((void *)(payload + 5) <= data_end &&
        payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D' && payload[4] == ' ') {
        return 1;
    }

    if ((void *)(payload + 4) <= data_end &&
        payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ') {
        return 1;
    }

    if ((void *)(payload + 7) <= data_end &&
        payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E' &&
        payload[4] == 'T' && payload[5] == 'E' && payload[6] == ' ') {
        return 1;
    }

    if ((void *)(payload + 8) <= data_end &&
        payload[0] == 'O' && payload[1] == 'P' && payload[2] == 'T' && payload[3] == 'I' &&
        payload[4] == 'O' && payload[5] == 'N' && payload[6] == 'S' && payload[7] == ' ') {
        return 1;
    }

    if ((void *)(payload + 6) <= data_end &&
        payload[0] == 'P' && payload[1] == 'A' && payload[2] == 'T' && payload[3] == 'C' &&
        payload[4] == 'H' && payload[5] == ' ') {
        return 1;
    }

    if ((void *)(payload + 8) <= data_end &&
        payload[0] == 'C' && payload[1] == 'O' && payload[2] == 'N' && payload[3] == 'N' &&
        payload[4] == 'E' && payload[5] == 'C' && payload[6] == 'T' && payload[7] == ' ') {
        return 1;
    }

    if ((void *)(payload + 6) <= data_end &&
        payload[0] == 'T' && payload[1] == 'R' && payload[2] == 'A' && payload[3] == 'C' &&
        payload[4] == 'E' && payload[5] == ' ') {
        return 1;
    }

    if ((void *)(payload + 24) <= data_end &&
        payload[0] == 'P' && payload[1] == 'R' && payload[2] == 'I' && payload[3] == ' ' &&
        payload[4] == '*' && payload[5] == ' ' && payload[6] == 'H' && payload[7] == 'T' &&
        payload[8] == 'T' && payload[9] == 'P' && payload[10] == '/' && payload[11] == '2' &&
        payload[12] == '.' && payload[13] == '0' && payload[14] == '\r' && payload[15] == '\n' &&
        payload[16] == '\r' && payload[17] == '\n' && payload[18] == 'S' && payload[19] == 'M' &&
        payload[20] == '\r' && payload[21] == '\n' && payload[22] == '\r' && payload[23] == '\n') {
        return 1;
    }

    return 0;
}

static __always_inline int is_tls_client_hello(unsigned char *payload, void *data_end) {
    if ((void *)(payload + 6) > data_end) {
        return 0;
    }

    if (payload[0] != 0x16) {
        return 0;
    }

    if (payload[1] != 0x03) {
        return 0;
    }

    if (payload[2] < 0x01 || payload[2] > 0x04) {
        return 0;
    }

    if (payload[5] != 0x01) {
        return 0;
    }

    return 1;
}

static __always_inline int is_service_port(__u16 port) {
    return port == bpf_htons(80) || port == bpf_htons(443);
}

SEC("xdp")
int xdp_drop_func(struct xdp_md *ctx) {
    __u32 stats_key = 0;
    struct stats *st = bpf_map_lookup_elem(&xdp_stats, &stats_key);

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        count_allowed(st);
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        count_allowed(st);
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        count_allowed(st);
        return XDP_PASS;
    }

    __u32 src_ip = ip->saddr;
    __u8 *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (blocked) {
        count_drop(st, DROP_BLOCKLIST);
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + sizeof(*eth) + ((__u32)ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) {
            count_drop(st, DROP_UDP);
            return XDP_DROP;
        }

        if (is_service_port(udp->dest)) {
            // UDP floods commonly replay an identical payload — fingerprint it.
            record_fingerprint((unsigned char *)(udp + 1), data_end);
            count_drop(st, DROP_UDP);
            return XDP_DROP;
        }

        count_allowed(st);
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_TCP) {
        count_allowed(st);
        return XDP_PASS;
    }

    __u32 ip_hdr_len = (__u32)ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip)) {
        count_drop(st, DROP_TCP_MALFORMED);
        return XDP_DROP;
    }

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

    if (!is_service_port(tcp->dest)) {
        count_allowed(st);
        return XDP_PASS;
    }

    struct conn_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    __u8 *allowed = bpf_map_lookup_elem(&allowed_flows, &key);
    if (allowed) {
        if (tcp->fin || tcp->rst) {
            bpf_map_delete_elem(&allowed_flows, &key);
        }
        count_allowed(st);
        return XDP_PASS;
    }

    if ((void *)payload == data_end) {
        count_allowed(st);
        return XDP_PASS;
    }

    if (tcp->dest == bpf_htons(80) && is_http_request(payload, data_end)) {
        __u8 value = 1;
        bpf_map_update_elem(&allowed_flows, &key, &value, BPF_ANY);
        count_allowed(st);
        return XDP_PASS;
    }

    if (tcp->dest == bpf_htons(443) && is_tls_client_hello(payload, data_end)) {
        __u8 value = 1;
        bpf_map_update_elem(&allowed_flows, &key, &value, BPF_ANY);
        count_allowed(st);
        return XDP_PASS;
    }

    // Payload-bearing junk on a service port: capture the signature and drop,
    // classifying by which service port it targeted.
    record_fingerprint(payload, data_end);
    if (tcp->dest == bpf_htons(80)) {
        count_drop(st, DROP_HTTP_INVALID);
    } else if (tcp->dest == bpf_htons(443)) {
        count_drop(st, DROP_TLS_INVALID);
    } else {
        count_drop(st, DROP_TCP_MALFORMED);
    }
    return XDP_DROP;
}

char _license[] SEC("license") = "Dual MIT/GPL";
