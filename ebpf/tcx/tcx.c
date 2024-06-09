/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

enum tcx_action_base {
	TCX_NEXT	= -1,
	TCX_PASS	= 0,
	TCX_DROP	= 2,
	TCX_REDIRECT	= 7,
};

SEC("tc/ingress")
int dummy(struct __sk_buff *skb)
{
    return TCX_NEXT;
}