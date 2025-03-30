//go:build ignore
/**
 * Copyright 2025 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

volatile const __be16 DPORT = bpf_htons(65535);

struct pseudo_header {
    __be32 src;
    __be32 dst;
    __u8 zero;
    __u8 proto;
    __be16 len;
};

SEC("xdp")
int xdp_fn(struct xdp_md *ctx)
{
    struct ethhdr *eth = (struct ethhdr *)(ctx_ptr(ctx, data)), eth_tmp;
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    __u8 buff[sizeof(struct pseudo_header)];
    struct pseudo_header *psh;
    __be32 saddr, daddr, seq;
    __u16 sport, dport;
    __u8 *tcp_flags;

    if ((void *) (tcph + 1) > ctx_ptr(ctx, data_end))
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;
    if (tcph->dest != DPORT)
        return XDP_PASS;

    /* swap eth addrs */
    __builtin_memcpy(&eth_tmp, eth, sizeof(struct ethhdr) - 2);
    __builtin_memcpy(eth->h_dest, eth_tmp.h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth_tmp.h_dest, ETH_ALEN);

    /* update iph */
    iph->ihl = 5;
    saddr = iph->saddr;
    daddr = iph->daddr;
    iph->saddr = daddr;
    iph->daddr = saddr;
    iph->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->check = ipv4_csum((void *)iph, sizeof(*iph));

    /* update tcph */
    sport = tcph->source;
    dport = tcph->dest;
    tcph->source = dport;
    tcph->dest = sport;
    seq = tcph->seq;
    tcph->seq = tcph->ack_seq;
    tcph->ack_seq = seq + bpf_htonl(0x1);
    tcph->doff = sizeof(struct tcphdr) >> 2;
    tcp_flags = (typeof(tcp_flags)) ((void *) tcph + offsetof(struct tcphdr, window) - 1);
    *tcp_flags = (TCP_FLAG_ACK | TCP_FLAG_RST) >> 8;

    /* calculate tcp checksum by referencing http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-2.htm */
    psh = (struct pseudo_header *) ((void *) tcph - sizeof(struct pseudo_header));
    __builtin_memcpy(buff, psh, sizeof(struct pseudo_header));
    psh->src = iph->saddr;
    psh->dst = iph->daddr;
    psh->zero = 0;
    psh->proto = IPPROTO_TCP;
    psh->len = bpf_htons(sizeof(struct tcphdr));
    tcph->check = 0;
    tcph->check = ipv4_csum(psh, sizeof(struct pseudo_header) + sizeof(struct tcphdr));
    __builtin_memcpy(psh, buff, sizeof(struct pseudo_header));

    return XDP_TX;
}
