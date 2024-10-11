//go:build ignore
/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

__noinline int
xdp_subprog(struct xdp_md *ctx)
{
    return ctx ? XDP_PASS : XDP_DROP;
}

static u32 count = 0;

SEC("xdp")
int xdp_fn(struct xdp_md *ctx)
{
    struct ethhdr *eth = (struct ethhdr *)(ctx_ptr(ctx, data));
    struct iphdr *iph = (struct iphdr *)(eth + 1);

    if ((void *)(iph + 1) > ctx_ptr(ctx, data_end))
        return XDP_PASS;

    if (iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // bpf_printk("xdp_fn: count=%d\n", count);
    count++;

    return xdp_subprog(ctx);
}
