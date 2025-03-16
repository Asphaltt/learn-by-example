/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

SEC("fentry/kprobe")
int BPF_PROG(fentry_kprobe, struct pt_regs *regs)
{
    bpf_printk("tcpconn, fentry_kprobe\n");

    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM1(regs);
    __handle_new_connection(ctx, sk, PROBE_TYPE_FENTRY, 0);

    return 0;
}

SEC("fexit/kprobe")
int BPF_PROG(fexit_kprobe, struct pt_regs *regs, int retval)
{
    bpf_printk("tcpconn, fexit_kprobe\n");

    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM1(regs);
    __handle_new_connection(ctx, sk, PROBE_TYPE_FEXIT, retval);

    return 0;
}