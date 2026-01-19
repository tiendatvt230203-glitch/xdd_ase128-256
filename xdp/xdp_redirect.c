/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDP Program - Redirect packets to userspace via AF_XDP
 * Filter by destination/source IP network
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* XSKMAP for AF_XDP sockets */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

/*
 * Config map:
 *   config[0] = remote_net (network address)
 *   config[1] = remote_mask (network mask)
 *   config[2] = direction (0=TX check dst, 1=RX check src)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

/* Statistics */
struct stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 redirected;
    __u64 passed;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 key = 0;
    struct stats *s;

    /* Update statistics */
    s = bpf_map_lookup_elem(&stats_map, &key);
    if (s) {
        s->rx_packets++;
        s->rx_bytes += (data_end - data);
    }

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only handle IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IP header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Get config */
    __u32 k = 0;
    __u32 *remote_net = bpf_map_lookup_elem(&config, &k);
    k = 1;
    __u32 *remote_mask = bpf_map_lookup_elem(&config, &k);
    k = 2;
    __u32 *direction = bpf_map_lookup_elem(&config, &k);

    if (!remote_net || !remote_mask || !direction) {
        if (s) s->passed++;
        return XDP_PASS;
    }

    /* Check IP based on direction */
    __u32 check_ip;
    if (*direction == 0) {
        /* TX direction: check destination IP */
        check_ip = bpf_ntohl(ip->daddr);
    } else {
        /* RX direction: check source IP */
        check_ip = bpf_ntohl(ip->saddr);
    }

    /* Filter by network */
    if ((check_ip & *remote_mask) != (*remote_net & *remote_mask)) {
        if (s) s->passed++;
        return XDP_PASS;
    }

    /* Redirect to AF_XDP socket if registered */
    __u32 idx = 0;
    if (bpf_map_lookup_elem(&xsks_map, &idx)) {
        if (s) s->redirected++;
        return bpf_redirect_map(&xsks_map, idx, XDP_DROP);
    }

    if (s) s->passed++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
