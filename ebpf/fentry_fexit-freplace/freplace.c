/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

//go:build ignore

#include "bpf_all.h"

SEC("freplace/stub_handler")
int freplace_handler()
{
    bpf_printk("freplace, replaced handler\n");

    return 0;
}