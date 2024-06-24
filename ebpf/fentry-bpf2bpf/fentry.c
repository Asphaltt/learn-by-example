/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

static __u32 count = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} prog_array SEC(".maps");

SEC("fentry/bpf2bpf")
int BPF_PROG(fentry_bpf2bpf, struct pt_regs *regs, struct sock *sk)
{
    bpf_printk("tcpconn, fentry_bpf2bpf\n");

    __handle_new_connection(ctx, sk, PROBE_TYPE_FENTRY, 0);

    if (count++ < 50)
        bpf_tail_call_static(ctx, &prog_array, 0);

    return 0;
}
