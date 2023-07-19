/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

struct sock_args {
    struct sock *sk;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct sock_args);
    __uint(max_entries, 1);
} socks SEC(".maps");

__noinline int
stub_handler()
{
    bpf_printk("freplace, stub handler\n");

    return 0;
}

SEC("kprobe/tcp_connect")
int k_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM1(ctx);

    struct sock_args args = {
        .sk = sk,
    };

    __u32 key = 0;
    bpf_map_update_elem(&socks, &key, &args, BPF_ANY);

    __handle_new_connection(ctx, sk, PROBE_TYPE_DEFAULT, 0);

    return stub_handler();
}

SEC("kprobe/inet_csk_complete_hashdance")
int k_icsk_complete_hashdance(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM2(ctx);

    struct sock_args args = {
        .sk = sk,
    };

    __u32 key = 0;
    bpf_map_update_elem(&socks, &key, &args, BPF_ANY);

    __handle_new_connection(ctx, sk, PROBE_TYPE_DEFAULT, 0);

    return stub_handler();
}