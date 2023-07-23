/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */
//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 4);
    __uint(max_entries, 1);
} progs SEC(".maps");

SEC("kprobe/hanle_new_connection")
int handle_new_connection(struct pt_regs *ctx)
{
    bpf_printk("tcpconn, handle_new_connection\n");

    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM1(ctx);
    __handle_new_connection(ctx, sk, PROBE_TYPE_DEFAULT, 0);

    return 0;
}

SEC("kprobe/tcp_connect")
int k_tcp_connect(struct pt_regs *ctx)
{
    bpf_tail_call_static(ctx, &progs, 0);

    return 0;
}

SEC("kprobe/inet_csk_complete_hashdance")
int k_icsk_complete_hashdance(struct pt_regs *ctx)
{
    bpf_tail_call_static(ctx, &progs, 0);

    return 0;
}