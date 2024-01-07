/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} prog_array SEC(".maps");

SEC("xdp")
int xdp_prog1(struct xdp_md *ctx)
{
    bpf_printk("tailcall-in-bpf2bpf: xdp_prog1\n");

    return XDP_PASS;
}

static __noinline int
tailcall1(struct xdp_md *ctx)
{
    int retval = XDP_ABORTED;

    bpf_tail_call_static(ctx, &prog_array, 0);

    return retval;
}

static __noinline int
tailcall2(struct xdp_md *ctx)
{
    volatile int retval = XDP_ABORTED;

    bpf_tail_call_static(ctx, &prog_array, 0);

    return retval;
}

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
    struct ethhdr *eth;
    struct iphdr *iph;
    int retval;

    eth = (struct ethhdr *) ctx_ptr(ctx, data);
    iph = (struct iphdr *)(eth + 1);

    if ((void *) (iph + 1) > ctx_ptr(ctx, data_end))
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP) || iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    bpf_printk("tailcall-in-bpf2bpf: xdp_entry\n");

    retval = tailcall1(ctx);
    bpf_printk("tailcall-in-bpf2bpf: tailcall1 retval: %d (0:aborted 1:drop 2:pass 3:tx 4:redirect)\n", retval);

    retval = tailcall2(ctx);
    bpf_printk("tailcall-in-bpf2bpf: tailcall2 retval: %d (0:aborted 1:drop 2:pass 3:tx 4:redirect)\n", retval);

    return XDP_PASS;
}
