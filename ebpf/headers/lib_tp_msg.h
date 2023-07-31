// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT
#ifndef __LIB_TP_MSG_H_
#define __LIB_TP_MSG_H_

#include "bpf_all.h"

enum probing_type {
    PROBE_TYPE_DEFAULT = 0,
    PROBE_TYPE_FENTRY,
    PROBE_TYPE_FEXIT,
    PROBE_TYPE_FREPLACE,
};

struct errmsg {
    char msg[64];
    __u16 len;
    __u8 probe_type;
    __u8 retval;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} errmsg_pb SEC(".maps");

static __always_inline void
__output_msg(void *ctx, char *msg, enum probing_type probe_type, int retval)
{
    struct errmsg errmsg;
    long len = bpf_probe_read_kernel_str(&errmsg.msg, sizeof(errmsg.msg), msg);

    errmsg.len = len;
    errmsg.probe_type = probe_type;
    errmsg.retval = retval;
    bpf_perf_event_output(ctx, &errmsg_pb, BPF_F_CURRENT_CPU, &errmsg,
        sizeof(errmsg));
}

#endif // __LIB_TP_MSG_H_