//go:build ignore
/**
 * Copyright 2025 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

struct tp__netif_receive_skb_args {
    unsigned long long __unused;

    struct sk_buff *skb;
};

SEC("tp/net/netif_receive_skb")
int tp__netif_receive_skb(struct tp__netif_receive_skb_args *args)
{
    struct sk_buff *skb = args->skb;
    struct ethhdr *eth = (typeof(eth)) (BPF_CORE_READ(skb, head) +
                                        BPF_CORE_READ(skb, mac_header));
    struct iphdr *ip = (typeof(ip)) (eth + 1);
    struct udphdr *udp = (typeof(udp)) (ip + 1);

    if (BPF_CORE_READ(eth, h_proto) == bpf_htons(ETH_P_IP) &&
        BPF_CORE_READ(ip, protocol) == IPPROTO_ICMP)
        bpf_printk("tp__netif_receive_skb: %d\n", BPF_CORE_READ(ip, protocol));

    return BPF_OK;
}