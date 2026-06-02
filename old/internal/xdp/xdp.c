//go:build ignore

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

// Helper for byte swapping if needed (e.g. __builtin_bswap16)
#define bpf_htons(x) ((__u16)(__builtin_constant_p(x) ? \
    (((__u16)(x) & 0xffU) << 8) | (((__u16)(x) & 0xff00U) >> 8) : \
    __builtin_bswap16(x)))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map_def SEC("maps") blocklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 100000,
};

struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct bpf_map_def SEC("maps") allowed_flows = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct conn_key),
    .value_size = sizeof(__u8),
    .max_entries = 262144,
};

struct stats {
    __u64 allowed;
    __u64 blocked;
};

struct bpf_map_def SEC("maps") xdp_stats = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct stats),
    .max_entries = 1,
};

static __always_inline void count_allowed(struct stats *st) {
    if (st) __sync_fetch_and_add(&st->allowed, 1);
}

static __always_inline void count_blocked(struct stats *st) {
    if (st) __sync_fetch_and_add(&st->blocked, 1);
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
        count_blocked(st);
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + sizeof(*eth) + ((__u32)ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) {
            count_blocked(st);
            return XDP_DROP;
        }

        if (is_service_port(udp->dest)) {
            count_blocked(st);
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
        count_blocked(st);
        return XDP_DROP;
    }

    struct tcphdr *tcp = data + sizeof(*eth) + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end) {
        count_blocked(st);
        return XDP_DROP;
    }

    __u32 tcp_hdr_len = (__u32)tcp->doff * 4;
    if (tcp_hdr_len < sizeof(*tcp)) {
        count_blocked(st);
        return XDP_DROP;
    }

    unsigned char *payload = (unsigned char *)tcp + tcp_hdr_len;
    if ((void *)payload > data_end) {
        count_blocked(st);
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

    count_blocked(st);
    return XDP_DROP;
}

char _license[] SEC("license") = "Dual MIT/GPL";
