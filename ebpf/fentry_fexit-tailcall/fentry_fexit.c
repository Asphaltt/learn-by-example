/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} socks SEC(".maps");

SEC("fentry/tailcall")
int BPF_PROG(fentry_tailcall, struct pt_regs *regs)
{
    bpf_printk("tcpconn, fentry_tailcall\n");

    __u32 key = 0;
    struct sock **skp = bpf_map_lookup_elem(&socks, &key);
    if (!skp)
        return 0;

    struct sock *sk = *skp;
    __handle_new_connection(ctx, sk, PROBE_TYPE_FENTRY, 0);

    return 0;
}

SEC("fexit/tailcall")
int BPF_PROG(fexit_tailcall, struct pt_regs *regs, int retval)
{
    bpf_printk("tcpconn, fexit_tailcall\n");

    __u32 key = 0;
    struct sock **skp = bpf_map_lookup_and_delete(&socks, &key);
    if (!skp)
        return 0;

    struct sock *sk = *skp;
    __handle_new_connection(ctx, sk, PROBE_TYPE_FEXIT, retval);

    return 0;
}