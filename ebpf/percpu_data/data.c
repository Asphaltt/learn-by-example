/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

static SEC(".data.__percpu") __u32 cnt0 = 0;
static SEC(".data.__percpu") __u32 cnt1 = 0;

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    if (ctx->rx_queue_index == 0) {
        cnt0++;
    } else {
        cnt1++;
    }

    __u32 cpu = bpf_get_smp_processor_id();
    bpf_printk("cpu: %u, cnt0: %u, cnt1: %u\n", cpu, cnt0, cnt1);

    return XDP_PASS;
}
