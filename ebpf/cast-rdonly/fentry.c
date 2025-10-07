//go:build ignore
/**
 * Copyright 2025 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

volatile const __u32 btf_id = 3620;

SEC("fentry/icmp_rcv")
int BPF_PROG(fentry_icmp_rcv)
{
    __u64 n = 0xffffffffff600000 - 0x800000a00000 + 0xfedc;
    struct sk_buff *skb;

    skb = (typeof(skb)) bpf_rdonly_cast((void *)n, btf_id);
    bpf_printk("XXX: %d\n", skb->len);
    return 0;
}
