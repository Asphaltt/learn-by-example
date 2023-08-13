/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_xdp_tc.h"

#define target_cpu 2

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __type(key, u32);
    __type(value, struct bpf_cpumap_val);
    __uint(max_entries, 6);
} redirect_map SEC(".maps");

static __always_inline void
handle_xdp(struct xdp_md *xdp, enum probing_type type, int cpu)
{
    void *data_end = ctx_ptr(xdp, data_end);
    void *data = ctx_ptr(xdp, data);
    struct ethhdr *eth = data;
    struct iphdr *iph;

    iph = data + sizeof(*eth);
    if (__IS_INVALID_HDR(iph, data_end))
        return;

    __handle_packet(xdp, iph, type, cpu);
}

static __always_inline bool
__is_icmp(struct xdp_md *xdp)
{
    void *data_end = ctx_ptr(xdp, data_end);
    void *data = ctx_ptr(xdp, data);
    struct ethhdr *eth = data;
    struct iphdr *iph;

    iph = data + sizeof(*eth);
    if (__IS_INVALID_HDR(iph, data_end))
        return false;

    return iph->protocol == IPPROTO_ICMP;
}

SEC("xdp/native")
int xdp_native(struct xdp_md *ctx)
{
    if (!__is_icmp(ctx))
        return XDP_PASS;

    u32 cpu = bpf_get_smp_processor_id();

    handle_xdp(ctx, PROBE_TYPE_DEFAULT, cpu);

    return bpf_redirect_map(&redirect_map, target_cpu, 0);
}

SEC("xdp_cpumap/3")
int xdp_cpumap(struct xdp_md *ctx)
{
    int cpu = bpf_get_smp_processor_id();

    handle_xdp(ctx, PROBE_TYPE_FENTRY, cpu);

    return XDP_PASS;
}