// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

#ifndef __LIB_XDP_TC_H_
#define __LIB_XDP_TC_H_

#include "bpf_all.h"

enum probing_type {
    PROBE_TYPE_DEFAULT = 0,
    PROBE_TYPE_FENTRY,
    PROBE_TYPE_FEXIT,
    PROBE_TYPE_FREPLACE,
};

typedef struct event {
    __be32 saddr, daddr;
    __u8 probe_type;
    __u8 verdict;
    __u16 pad;
} __attribute__((packed)) event_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 4);
} events SEC(".maps");

static __always_inline void
__handle_packet(void *ctx, struct iphdr *iph, enum probing_type type, int verdict)
{
    event_t ev = {};
    ev.saddr = BPF_CORE_READ(iph, saddr);
    ev.daddr = BPF_CORE_READ(iph, daddr);
    ev.probe_type = (__u8)type;
    ev.verdict = (__u8)verdict;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
}

#endif // __LIB_XDP_TC_H_