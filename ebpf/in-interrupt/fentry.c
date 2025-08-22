//go:build ignore
/**
 * Copyright 2025 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bpf_all.h"

int run_icmp;
int in_interrupt_icmp_rcv;

int run_tcp;
int in_interrupt_tcp_connect;

extern int bpf_in_interrupt(void) __weak __ksym;

SEC("fentry/icmp_rcv")
int BPF_PROG(fentry__icmp_rcv)
{
    if (run_icmp)
        return BPF_OK;
    run_icmp = 1;

    in_interrupt_icmp_rcv = bpf_in_interrupt();
    return BPF_OK;
}

SEC("fentry/tcp_connect")
int BPF_PROG(fentry__tcp_connect)
{
    if (run_tcp)
        return BPF_OK;
    run_tcp = 1;

    in_interrupt_tcp_connect = bpf_in_interrupt();
    return BPF_OK;
}
