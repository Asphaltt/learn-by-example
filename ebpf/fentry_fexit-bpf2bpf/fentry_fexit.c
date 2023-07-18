/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

SEC("fentry/bpf2bpf")
int BPF_PROG(fentry_bpf2bpf, struct pt_regs *regs, struct sock *sk)
{
    bpf_printk("tcpconn, fentry_bpf2bpf\n");

    __handle_new_connection(ctx, sk, PROBE_TYPE_FENTRY, 0);

    return 0;
}

SEC("fexit/bpf2bpf")
int BPF_PROG(fexit_bpf2bpf, struct pt_regs *regs, struct sock *sk, int retval)
{
    bpf_printk("tcpconn, fexit_bpf2bpf\n");

    __handle_new_connection(ctx, sk, PROBE_TYPE_FEXIT, retval);

    return 0;
}