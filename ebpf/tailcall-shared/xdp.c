//go:build ignore
/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 4);
    __uint(max_entries, 1);
} progs SEC(".maps");

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
    bpf_printk("tcpconn, xdp_entry\n");

    bpf_tail_call_static(ctx, &progs, 0);

    return XDP_PASS;
}
