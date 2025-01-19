//go:build ignore
/**
 * Copyright 2025 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("tp_btf/netif_receive_skb")
int BPF_PROG(tp_btf_netif_receive_skb, struct sk_buff *skb)
{
    struct ethhdr *eth = (typeof(eth)) (BPF_CORE_READ(skb, head) +
                                        BPF_CORE_READ(skb, mac_header));
    struct iphdr *ip = (typeof(ip)) (eth + 1);
    struct udphdr *udp = (typeof(udp)) (ip + 1);
    __u64 skbaddr = (unsigned long)skb;
    __u64 flags;

    if (BPF_CORE_READ(eth, h_proto) == bpf_htons(ETH_P_IP) &&
        BPF_CORE_READ(ip, protocol) == IPPROTO_ICMP)
        bpf_printk("tp_btf_netif_receive_skb: %d\n", BPF_CORE_READ(ip, protocol));

    flags = ((__u64) (14 + 20 + 8)) << 32 | BPF_F_CURRENT_CPU;
    if (BPF_CORE_READ(eth, h_proto) == bpf_htons(ETH_P_IP) &&
        BPF_CORE_READ(ip, protocol) == IPPROTO_UDP && BPF_CORE_READ(udp, dest) == bpf_htons(65535))
        bpf_skb_output(skb, &events, flags, &skbaddr, sizeof(skbaddr));

    return BPF_OK;
}