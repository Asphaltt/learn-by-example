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

SEC("fentry/netlink_extack")
int BPF_PROG(fentry_netlink_extack, struct netlink_extack_error_ctx *nl_ctx)
{
    bpf_printk("tcpconn, fentry_netlink_extack\n");

    /*
     * BPF_CORE_READ() is not dedicated to user-defined struct.
     */

    __u32 msg;
    bpf_probe_read(&msg, sizeof(msg), &nl_ctx->msg);
	char *c = (void *)(__u64) ((void *) nl_ctx + (__u64) (msg & 0xFFFF));

	__output_msg(ctx, c, PROBE_TYPE_FENTRY, 0);

    return 0;
}

SEC("fexit/netlink_extack")
int BPF_PROG(fexit_netlink_extack, struct netlink_extack_error_ctx *nl_ctx, int retval)
{
    bpf_printk("tcpconn, fexit_netlink_extack\n");

    __u32 msg;
    bpf_probe_read(&msg, sizeof(msg), &nl_ctx->msg);
	char *c = (void *)(__u64) ((void *) nl_ctx + (__u64) (msg & 0xFFFF));

	__output_msg(ctx, c, PROBE_TYPE_FEXIT, retval);

    return 0;
}