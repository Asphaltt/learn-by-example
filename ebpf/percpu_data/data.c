/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

static SEC(".data.__percpu") __u32 cnt = 0;

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    cnt++;

    __u32 cpu = bpf_get_smp_processor_id();
    bpf_printk("cpu: %u, cnt: %u\n", cpu, cnt);

    return XDP_PASS;
}
