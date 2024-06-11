/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_xdp_tc.h"

static __always_inline void
handle_tc(void *ctx, struct sk_buff *skb, enum probing_type type, int verdict)
{
    void *head = (void *)(long)BPF_CORE_READ(skb, head);
    __u16 l2_off = BPF_CORE_READ(skb, mac_header);
    __u16 l3_off = BPF_CORE_READ(skb, network_header);
    struct ethhdr *eth = head + l2_off;
    struct iphdr *iph = head + l3_off;

    if (BPF_CORE_READ(eth, h_proto) != bpf_htons(ETH_P_IP))
        return;

    if (BPF_CORE_READ(iph, protocol) != IPPROTO_ICMP)
        return;

    __handle_packet(ctx, iph, type, verdict);
}

SEC("fentry/tc")
int BPF_PROG(fentry_tc, struct sk_buff *skb)
{
    handle_tc(ctx, skb, PROBE_TYPE_FENTRY, 0);
    return 0;
}

SEC("fexit/tc")
int BPF_PROG(fexit_tc, struct sk_buff *skb, int verdict)
{
    handle_tc(ctx, skb, PROBE_TYPE_FEXIT, verdict);
    return 0;
}

SEC("tc")
int dummy(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

__noinline int
subprog1(void)
{
	bpf_printk("Here's subprog1.\n");

    return 0;
}

__noinline int
subprog2(void)
{
	bpf_printk("Here's subprog2.\n");

    return 0;
}

__noinline int
subprog3(void)
{
	bpf_printk("Here's subprog3.\n");

    return 0;
}

SEC("tc")
int entry1(struct __sk_buff *skb)
{
	subprog1();
	subprog2();

	return TC_ACT_OK;
}

SEC("tc")
int entry2(struct __sk_buff *skb)
{
	subprog3();

	return TC_ACT_OK;
}