/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_xdp_tc.h"

static __always_inline void
handle_xdp(void *ctx, struct xdp_buff *xdp, int verdict, bool is_fexit)
{
    struct ethhdr *eth = (void *)(long)BPF_CORE_READ(xdp, data);
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > (void *)(long)BPF_CORE_READ(xdp, data_end))
        return;

    if (BPF_CORE_READ(eth, h_proto) != bpf_htons(ETH_P_IP))
        return;

    if (BPF_CORE_READ(iph, protocol) != IPPROTO_ICMP)
        return;

    __handle_packet(ctx, iph, is_fexit ? PROBE_TYPE_FEXIT : PROBE_TYPE_FENTRY, verdict);
}

SEC("fentry/xdp")
int BPF_PROG(fentry_xdp, struct xdp_buff *xdp)
{
    handle_xdp(ctx, xdp, 0, false);
    return 0;
}

SEC("fexit/xdp")
int BPF_PROG(fexit_xdp, struct xdp_buff *xdp, int verdict)
{
    handle_xdp(ctx, xdp, verdict, true);
    return 0;
}

SEC("xdp")
int dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
}