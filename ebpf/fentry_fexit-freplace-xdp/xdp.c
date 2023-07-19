/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_xdp_tc.h"

__noinline int
stub_handler(struct xdp_md *ctx)
{
    bpf_printk("freplace, stub handler\n");

    return 0;
}

SEC("xdp")
int xdp_entry(struct xdp_md *xdp)
{
    stub_handler(xdp);
    return XDP_PASS;
}