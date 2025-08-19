//go:build ignore
/**
 * Copyright 2025 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "vmlinux.h"

#include "bpf_all.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, int);
} prog_array SEC(".maps");

__u32 run;

SEC("fentry/k_tcp_connect")
int BPF_PROG(tailcallee)
{
    return BPF_OK;
}

SEC("fentry/k_tcp_connect")
int BPF_PROG(fentry__k_tcp_connect, struct pt_regs *regs)
{
    struct sock *sk;

    if (run)
        return BPF_OK;
    run = 1;

    sk = (typeof(sk)) PT_REGS_PARM1_CORE(regs);
    bpf_tail_call(ctx, &prog_array, BPF_CORE_READ(sk, __sk_common.skc_hash));

    return BPF_OK;
}
