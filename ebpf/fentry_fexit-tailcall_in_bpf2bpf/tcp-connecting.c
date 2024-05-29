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

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} prog_array SEC(".maps");

__noinline int
stub_handler(struct pt_regs *ctx)
{
    volatile int ret = 33;

    bpf_printk("freplace, stub handler, ctx:%p retval:%d\n", ctx, ret);

    bpf_tail_call_static(ctx, &prog_array, 0);

    return ret;
}

SEC("kprobe/tailcall")
int k_tailcall(struct pt_regs *ctx)
{
    bpf_printk("tailcall, ctx:%p\n", ctx);

    return 55;
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

    int ret = stub_handler(ctx);
    bpf_printk("tcp_connect, ret:%d (exp 55, not 33)\n", ret);

    return BPF_OK;
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

    int ret = stub_handler(ctx);
    bpf_printk("icsk_complete_hashdance, ret:%d (exp 55, not 33)\n", ret);

    return BPF_OK;
}