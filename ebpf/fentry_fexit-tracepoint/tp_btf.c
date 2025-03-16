/**
 * Copyright 2025 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */
//go:build ignore

#include "bpf_all.h"

#include "lib_tp_msg.h"

SEC("tp_btf/netlink_extack")
int BPF_PROG(tp__netlink_extack, __u32 _msg)
{
	char *msg = (void *)(__u64) ((void *) ctx + (__u64) ((_msg) & 0xFFFF));

	__output_msg(ctx, msg, PROBE_TYPE_DEFAULT, 0);

	return 0;
}