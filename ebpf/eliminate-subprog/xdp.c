//go:build ignore/
/**
 * Copyright 2026 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bpf_all.h"

static __noinline void
subprog(int len, int ret)
{
    __sink(len);
    __sink(ret);
}

SEC("xdp")
int xdp_fn(struct xdp_md *ctx)
{
    struct ethhdr *eth = (struct ethhdr *)(ctx_ptr(ctx, data));
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    int len = ctx->data_end - ctx->data;
    int ret = XDP_PASS;

    if ((void *)(iph + 1) > ctx_ptr(ctx, data_end))
        return ret;

    if (iph->protocol != IPPROTO_ICMP)
        return ret;

    barrier_var(ret);
    subprog(len, ret);

    return ret;
}
