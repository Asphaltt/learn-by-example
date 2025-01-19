//go:build ignore

/**
 * Copyright 2025 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("fentry/__netif_receive_skb_core")
int BPF_PROG(fentry___netif_receive_skb_core, struct sk_buff **pskb)
{
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct iphdr *ip;

    bpf_probe_read_kernel(&skb, sizeof(skb), pskb);
    eth = (typeof(eth)) (BPF_CORE_READ(skb, head) +
                        BPF_CORE_READ(skb, mac_header));
    ip = (typeof(ip)) (eth + 1);

    if (BPF_CORE_READ(eth, h_proto) == bpf_htons(ETH_P_IP) &&
        BPF_CORE_READ(ip, protocol) == IPPROTO_ICMP)
        bpf_skb_output(ctx, &events, BPF_F_CURRENT_CPU, NULL, 0);

    return BPF_OK;
}