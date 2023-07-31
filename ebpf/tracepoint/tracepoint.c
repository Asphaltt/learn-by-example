/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */
//go:build ignore

#include "bpf_all.h"

#include "lib_tp_msg.h"

struct netlink_extack_error_ctx {
	unsigned long unused;

	/*
	 * bpf does not support tracepoint __data_loc directly.
	 *
	 * Actually, this field is a 32 bit integer whose value encodes
	 * information on where to find the actual data. The first 2 bytes is
	 * the size of the data. The last 2 bytes is the offset from the start
	 * of the tracepoint struct where the data begins.
	 * -- https://github.com/iovisor/bpftrace/pull/1542
	 */
	__u32 msg; // __data_loc char[] msg;
};

SEC("tp/netlink/netlink_extack")
int tp__netlink_extack(struct netlink_extack_error_ctx *ctx)
{
	char *msg = (void *)(__u64) ((void *) ctx + (__u64) ((ctx->msg) & 0xFFFF));

	__output_msg(ctx, msg, PROBE_TYPE_DEFAULT, 0);

	return 0;
}