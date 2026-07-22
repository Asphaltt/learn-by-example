//go:build ignore
/**
 * Copyright 2026 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bpf_all.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} pa SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    bpf_tail_call_static(ctx, &pa, 0);
    return XDP_PASS;
}

SEC("fexit")
int BPF_PROG(trace1)
{
    return BPF_OK;
}
