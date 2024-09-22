//go:build ignore
/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

void log_established(struct bpf_sock_ops *skops, bool passive)
{
    /* It's necessary to read them first. Or it cannot print the addrs
     * correctly.
     */
    /* dport is in big endian. */
    /* sport is in local endian, i.e. little endian. It should not use
     * bpf_ntohs() to convert the endian.
     */
    __be16 dport = skops->remote_port >> 16;
    __be32 daddr = skops->remote_ip4;
    __be32 saddr = skops->local_ip4;
    __u16 sport = skops->local_port;

    if (passive)
        bpf_printk("passive established: %pI4:%d -> %pI4:%d\n", &saddr,
                   sport, &daddr, bpf_ntohs(dport));
    else
        bpf_printk("active established: %pI4:%d -> %pI4:%d\n", &saddr,
                   sport, &daddr, bpf_ntohs(dport));
}

SEC("sockops")
int sockops_example(struct bpf_sock_ops *skops)
{
    __u32 op = skops->op;

    switch (op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        log_established(skops, false);
        break;

    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        log_established(skops, true);
        break;
    }

    return 0;
}
