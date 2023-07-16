// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

#ifndef __LIB_KPROBE_H_
#define __LIB_KPROBE_H_

#include "bpf_all.h"

enum probing_type {
    PROBE_TYPE_DEFAULT = 0,
    PROBE_TYPE_FENTRY,
    PROBE_TYPE_FEXIT,
    PROBE_TYPE_FREPLACE,
};

typedef struct event {
    __be32 saddr, daddr;
    __be16 sport, dport;
    __u8 probe_type;
    __u8 retval;
    __u16 pad;
} __attribute__((packed)) event_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 4);
} events SEC(".maps");

static __always_inline void
__handle_new_connection(void *ctx, struct sock *sk, enum probing_type type, int retval)
{
    event_t ev = {};

    ev.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ev.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    ev.probe_type = (__u8)type;
    ev.retval = (__u8)retval;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
}

#endif // __LIB_KPROBE_H_