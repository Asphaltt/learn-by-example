/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */
//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

static __noinline void
handle_new_connection(void *ctx, struct sock *sk)
{
    __handle_new_connection(ctx, sk, PROBE_TYPE_DEFAULT, 0);
}

SEC("kprobe/tcp_connect")
int k_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM1(ctx);

    handle_new_connection(ctx, sk);

    return 0;
}

SEC("kprobe/inet_csk_complete_hashdance")
int k_icsk_complete_hashdance(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM2(ctx);

    handle_new_connection(ctx, sk);

    return 0;
}