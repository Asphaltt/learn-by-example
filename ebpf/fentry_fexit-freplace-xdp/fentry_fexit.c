/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_xdp_tc.h"

SEC("fentry/freplace_handler")
int BPF_PROG(fentry_freplace_handler, struct xdp_buff *xdp)
{
    bpf_printk("fentry, freplace handler\n");

    struct ethhdr *eth = (void *)(long) BPF_CORE_READ(xdp, data);
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > (void *)(long) BPF_CORE_READ(xdp, data_end))
        return -1;

    if (BPF_CORE_READ(eth, h_proto) != bpf_htons(ETH_P_IP))
        return -1;

    if (BPF_CORE_READ(iph, protocol) != IPPROTO_ICMP)
        return -1;

    __handle_packet(ctx, iph, PROBE_TYPE_FENTRY, 0);

    return 0;
}

SEC("fexit/freplace_handler")
int BPF_PROG(fexit_freplace_handler, struct xdp_buff *xdp, int retval)
{
    bpf_printk("fexit, freplace handler\n");

    struct ethhdr *eth = (void *)(long) BPF_CORE_READ(xdp, data);
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > (void *)(long) BPF_CORE_READ(xdp, data_end))
        return -1;

    if (BPF_CORE_READ(eth, h_proto) != bpf_htons(ETH_P_IP))
        return -1;

    if (BPF_CORE_READ(iph, protocol) != IPPROTO_ICMP)
        return -1;

    __handle_packet(ctx, iph, PROBE_TYPE_FEXIT, 0);

    return 0;
}
