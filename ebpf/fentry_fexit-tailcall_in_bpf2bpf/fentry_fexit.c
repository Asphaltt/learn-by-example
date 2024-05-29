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

SEC("fentry/freplace_handler")
int BPF_PROG(fentry_freplace_handler, struct pt_regs *regs)
{
    bpf_printk("fentry, freplace handler, regs:%p\n", regs);

    __u32 key = 0;
    struct sock_args *args = bpf_map_lookup_elem(&socks, &key);
    if (!args)
        return 0;

    struct sock *sk = args->sk;
    __handle_new_connection(ctx, sk, PROBE_TYPE_FENTRY, 0);

    return 0;
}

SEC("fexit/freplace_handler")
int BPF_PROG(fexit_freplace_handler, struct pt_regs *regs, int retval)
{
    bpf_printk("fexit, freplace handler, regs:%p\n", regs);

    __u32 key = 0;
    struct sock_args *args = bpf_map_lookup_and_delete(&socks, &key);
    if (!args)
        return 0;

    struct sock *sk = args->sk;
    __handle_new_connection(ctx, sk, PROBE_TYPE_FEXIT, retval);

    return 0;
}
