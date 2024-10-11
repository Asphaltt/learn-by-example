//go:build ignore
/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} jmp_table SEC(".maps");

SEC("freplace/xdp_subprog")
int freplace_fn(struct xdp_md *ctx)
{
    bpf_tail_call_static(ctx, &jmp_table, 0);
    return XDP_PASS;
}
