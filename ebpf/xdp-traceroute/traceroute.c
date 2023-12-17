//go:build ignore

// SPDX-License-Identifier: GPL-2.0

#include "bpf_all.h"

#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/

static volatile const __u32 MY_ADDR = 0;

static __always_inline void
__update_icmp_checksum(struct icmphdr *icmph, int size)
{
    icmph->checksum = 0;
    icmph->checksum = ipv4_csum(icmph, size);
}

static __always_inline void
__update_ip_checksum(struct iphdr *iph)
{
    iph->check = 0;
    iph->check = ipv4_csum(iph, sizeof(*iph));
}

static __always_inline int
__trim_payload(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph,
               __u64 *icmp_payload)
{
    int pkt_len = ctx->data_end - ctx->data, trim_size;
    int payload_len, iph_len = sizeof(*iph);
    struct icmphdr *icmph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    bool move_hdr = iph->ihl != 5;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        payload_len = iph_len + sizeof(struct tcphdr);

        if (move_hdr) {
            tcph = (struct tcphdr *)((void *) iph + (iph->ihl << 2));
            if ((void *)(__u64) (tcph + 1) > ctx_ptr(ctx, data_end))
                return XDP_PASS;
            if ((void *)(__u64) (iph+1) + sizeof(*tcph) > ctx_ptr(ctx, data_end))
                return XDP_PASS;

            __builtin_memcpy(iph+1, tcph, sizeof(*tcph));
        }
        break;

    case IPPROTO_UDP:
        payload_len = iph_len + sizeof(struct udphdr);

        if (move_hdr) {
            udph = (struct udphdr *)((void *) iph + (iph->ihl << 2));
            if ((void *)(__u64) (udph + 1) > ctx_ptr(ctx, data_end))
                return XDP_PASS;
            if ((void *)(__u64) (iph+1) + sizeof(*udph) > ctx_ptr(ctx, data_end))
                return XDP_PASS;

            __builtin_memcpy(iph+1, udph, sizeof(*udph));
        }
        break;

    case IPPROTO_ICMP:
        payload_len = iph_len + sizeof(struct icmphdr);

        if (move_hdr) {
            icmph = (struct icmphdr *)((void *) iph + (iph->ihl << 2));
            if ((void *)(__u64) (icmph + 1) > ctx_ptr(ctx, data_end))
                return XDP_PASS;
            if ((void *)(__u64) (iph+1) + sizeof(*icmph) > ctx_ptr(ctx, data_end))
                return XDP_PASS;

            __builtin_memcpy(iph+1, icmph, sizeof(*icmph));
        }
        break;

    default:
        return XDP_PASS;
    }

    *icmp_payload = payload_len;
    trim_size = pkt_len - sizeof(*eth) - payload_len;
    if (trim_size < 0)
        return XDP_PASS;

    if (trim_size > 0 && bpf_xdp_adjust_tail(ctx, -trim_size))
        return XDP_PASS;

    return 0;
}

static __always_inline int
__expand_icmp_headroom(struct xdp_md *ctx)
{
    const int siz = (sizeof(struct iphdr) + sizeof(struct icmphdr));

    return bpf_xdp_adjust_head(ctx, -siz);
}

static __always_inline int
__encode_icmp_packet(struct xdp_md *ctx, struct ethhdr *org_eth,
                     __u64 icmp_payload, __u32 sip, __u16 id)
{
    struct ethhdr *eth = (struct ethhdr *) ctx_ptr(ctx, data);
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    struct icmphdr *icmph = (struct icmphdr *)(iph + 1);

    if ((void *)(__u64) (icmph + 1) + icmp_payload > ctx_ptr(ctx, data_end))
        return XDP_PASS;

    __builtin_memcpy(eth->h_dest, org_eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, org_eth->h_dest, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IP);

    iph->version = 4;
    iph->ihl = sizeof(*iph) >> 2;
    iph->tos = 0x2b; // Custom TOS to identify the packet.
    iph->tot_len = bpf_htons(sizeof(*iph) + sizeof(*icmph) + icmp_payload);
    iph->id = id;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = MY_ADDR;
    iph->daddr = sip;
    __update_ip_checksum(iph);

    icmph->type = ICMP_TIME_EXCEEDED;
    icmph->code = ICMP_EXC_TTL;
    icmph->un.gateway = 0;
    __update_icmp_checksum(icmph, sizeof(*icmph) + icmp_payload);

    return XDP_TX;
}

SEC("xdp")
int traceroute(struct xdp_md *ctx)
{
    struct ethhdr *eth = (struct ethhdr *) ctx_ptr(ctx, data), copied;
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    __u64 icmp_payload;
    __u32 sip;
    __u16 id;

    if ((void *)(__u64) (iph + 1) > ctx_ptr(ctx, data_end))
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    if (iph->ttl > 1)
        return XDP_PASS;

    sip = iph->saddr;
    id = iph->id;

    __builtin_memcpy(&copied, eth, sizeof(copied));

    if (__trim_payload(ctx, eth, iph, &icmp_payload))
        return XDP_PASS;

    if (__expand_icmp_headroom(ctx))
        return XDP_PASS;

    return __encode_icmp_packet(ctx, &copied, icmp_payload, sip, id);
}