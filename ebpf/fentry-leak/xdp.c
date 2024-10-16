/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

//go:build ignore

#include "bpf_all.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, 4);
    __uint(value_size, 4);
} jmp_table SEC(".maps");

SEC("fentry/xdp")
int BPF_PROG(fentry_xdp, struct xdp_buff *xdp)
{
    int ret = BPF_OK;

    bpf_tail_call_static(ctx, &jmp_table, 0);
    return ret;
}

SEC("xdp")
int dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
}