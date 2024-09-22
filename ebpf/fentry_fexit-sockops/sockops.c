//go:build ignore
/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

#define BPF_SOCK_OPS_MAX (BPF_SOCK_OPS_WRITE_HDR_OPT_CB + 1)

struct sock_option {
    char name[32];
};

SEC(".data.options")
struct sock_option options[] = {
    [BPF_SOCK_OPS_VOID]                     = { .name = "VOID" },
    [BPF_SOCK_OPS_TIMEOUT_INIT]             = { .name = "TIMEOUT_INIT" },
    [BPF_SOCK_OPS_RWND_INIT]                = { .name = "RWND_INIT" },
    [BPF_SOCK_OPS_TCP_CONNECT_CB]           = { .name = "TCP_CONNECT_CB" },
    [BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB]    = { .name = "ACTIVE_ESTABLISHED_CB" },
    [BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB]   = { .name = "PASSIVE_ESTABLISHED_CB" },
    [BPF_SOCK_OPS_NEEDS_ECN]                = { .name = "NEEDS_ECN" },
    [BPF_SOCK_OPS_BASE_RTT]                 = { .name = "BASE_RTT" },
    [BPF_SOCK_OPS_RTO_CB]                   = { .name = "RTO_CB" },
    [BPF_SOCK_OPS_RETRANS_CB]               = { .name = "RETRANS_CB" },
    [BPF_SOCK_OPS_STATE_CB]                 = { .name = "STATE_CB" },
    [BPF_SOCK_OPS_TCP_LISTEN_CB]            = { .name = "TCP_LISTEN_CB" },
    [BPF_SOCK_OPS_RTT_CB]                   = { .name = "RTT_CB" },
    [BPF_SOCK_OPS_PARSE_HDR_OPT_CB]         = { .name = "PARSE_HDR_OPT_CB" },
    [BPF_SOCK_OPS_HDR_OPT_LEN_CB]           = { .name = "HDR_OPT_LEN_CB" },
    [BPF_SOCK_OPS_WRITE_HDR_OPT_CB]         = { .name = "WRITE_HDR_OPT_CB" },
};

SEC("fentry")
int BPF_PROG(fentry_sockops, struct bpf_sock_ops_kern *skops)
{
    __u8 op = BPF_CORE_READ(skops, op);

    if (op >= BPF_SOCK_OPS_MAX)
        return BPF_OK;

    op &= 0xF; /* Make sure op as a correct index of options. */
    bpf_printk("fentry sockops: %s\n", options[op].name);

    return BPF_OK;
}

SEC("fexit")
int BPF_PROG(fexit_sockops, struct bpf_sock_ops_kern *skops, int retval)
{
    __u8 op = BPF_CORE_READ(skops, op);

    if (op >= BPF_SOCK_OPS_MAX)
        return BPF_OK;

    op &= 0xF; /* Make sure op as a correct index of options. */
    bpf_printk("fexit  sockops: %s, retval: %d\n", options[op].name, retval);

    return BPF_OK;
}
