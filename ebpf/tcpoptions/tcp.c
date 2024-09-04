/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

static __always_inline bool
__check(void *data, void *data_end, int length)
{
    return data + length <= data_end;
}

__noinline int
option_parser(struct xdp_md *xdp, int offset)
{
    int ret = 0;

    barrier_var(ret);
    barrier_var(offset);
    return xdp ? 1 : ret;
}

static void
__parse_options(struct xdp_md *xdp, struct tcphdr *tcph)
{
    int length = (tcph->doff << 2) - sizeof(struct tcphdr);
    int offset;

    /* Initialize offset to tcp options part. */
    offset = (void *) (tcph + 1) - ctx_ptr(xdp, data);;

    for (int i = 0; i < ((1<<4 /* bits number of doff */)<<2)-sizeof(struct tcphdr); i++) {
        if (length <= 0)
            break;

        int ret = option_parser(xdp, offset);
        if (ret <= 0)
            break;

        offset += ret;
        length -= ret;
    }
}

SEC("xdp")
int xdp_tops(struct xdp_md *xdp)
{
    struct iphdr *iph = ctx_ptr(xdp, data) + sizeof(struct ethhdr);
    struct tcphdr *tcph = (typeof(tcph)) (iph + 1);

    if (!__check(tcph, ctx_ptr(xdp, data_end), sizeof(*tcph)))
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __parse_options(xdp, tcph);

    return XDP_PASS;
}
