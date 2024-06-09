/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_xdp_tc.h"

SEC("freplace/stub_handler")
int freplace_handler(struct xdp_md *xdp)
{
    struct ethhdr *eth = (void *)(long) xdp->data;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > (void *)(long) xdp->data_end)
        return 0;

    if (BPF_CORE_READ(eth, h_proto) != bpf_htons(ETH_P_IP))
        return 0;

    if (BPF_CORE_READ(iph, protocol) != IPPROTO_ICMP)
        return 0;

    __handle_packet(xdp, iph, PROBE_TYPE_FREPLACE, 0);

    bpf_printk("freplace, replaced handler\n");

    return 0;
}