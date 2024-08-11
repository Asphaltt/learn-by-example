/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

#define MAX_TCPOPT_LEN 40

#define TCPOPT_EOL 0
#define TCPOPT_NOP 1

/* compatible mode */
#define TCPOPT_TOA_COMPAT  254
#define TCPOPT_TOA_AKAMAI  253

#define TCPOLEN_TOA 8		/* |opcode|size|ip+port| = 1 + 1 + 6 */

struct toa_data {
	__u8 opcode;
	__u8 opsize;
	__u16 port;
	__u32 ip;
};

static __always_inline bool
__read_toa_4(struct tcphdr *tcp, struct toa_data *toa)
{
    void *buff;
    int length;

    length  = BPF_CORE_READ_BITFIELD_PROBED(tcp, doff) << 2;
    length -= sizeof(struct tcphdr);

    buff = (void *) tcp + sizeof(struct tcphdr);

    while (length > 0) {
        __u8 opcode, opsize;

        /* bpf_probe_read_kernel() expects to read a toa option. If it fails to
         * read it, it won't be a toa option; then return false because there's
         * not enough data to read as a toa option.
         */
        if (bpf_probe_read_kernel(toa, sizeof(*toa), buff) < 0)
            return false;

        opcode = toa->opcode;
        opsize = toa->opsize;

        if (opcode == TCPOPT_EOL)
            return false;
        if (opcode == TCPOPT_NOP) { /* Ref: RFC 793 section 3.1 */
            buff++;
            length--;
            continue;
        }

        if (opsize < 2)             /* "silly options" */
            return false;
        if (opsize > length)        /* don't parse partial options */
            return false;

        if (opcode == TCPOPT_TOA_COMPAT || opcode == TCPOPT_TOA_AKAMAI) {
            if (opsize == TCPOLEN_TOA)
                return true;
        }

        buff += opsize;
        length -= opsize;
    }

    return false;
}

static __always_inline bool
__read_toa_3(struct tcphdr *tcp, struct toa_data *toa)
{
    void *buff;
    int length;

    length  = BPF_CORE_READ_BITFIELD_PROBED(tcp, doff) << 2;
    length -= sizeof(struct tcphdr);

    buff = (void *) tcp + sizeof(struct tcphdr);

    while (length > 0) {
        __u8 opcode, opsize;

        if (bpf_probe_read_kernel(&opcode, sizeof(opcode), buff) < 0)
            return false;

        if (opcode == TCPOPT_EOL)
            return false;
        if (opcode == TCPOPT_NOP) { /* Ref: RFC 793 section 3.1 */
            buff++;
            length--;
            continue;
        }

        if (bpf_probe_read_kernel(&opsize, sizeof(opsize), buff + 1) < 0)
            return false;

        if (opsize < 2)             /* "silly options" */
            return false;
        if (opsize > length)        /* don't parse partial options */
            return false;

        if (opcode == TCPOPT_TOA_COMPAT || opcode == TCPOPT_TOA_AKAMAI) {
            if (opsize == TCPOLEN_TOA) {
                if (bpf_probe_read_kernel(toa, sizeof(*toa), buff-2) < 0)
                    return false;
                return true;
            }
        }

        buff += opsize;
        length -= opsize;
    }

    return false;
}

struct toa_prober {
    struct toa_data *toa;
    int length;
    int offset;
};

static int
__probe_toa(struct toa_prober *prober, void *buff)
{
    if (prober->offset + sizeof(*prober->toa) > prober->length)
        return -1;

    if (bpf_probe_read_kernel(prober->toa, sizeof(*prober->toa), buff + prober->offset) < 0)
        return -1;

    if (prober->toa->opcode == TCPOPT_EOL)
        return -1;
    if (prober->toa->opcode == TCPOPT_NOP) {
        prober->offset++;
        return 0;
    }
    if (prober->toa->opsize < 2)                                /* "silly options" */
        return -1;
    if (prober->offset + prober->toa->opsize > prober->length)  /* don't parse partial options */
        return -1;
    if (prober->toa->opcode == TCPOPT_TOA_COMPAT || prober->toa->opcode == TCPOPT_TOA_AKAMAI) {
        if (prober->toa->opsize == TCPOLEN_TOA)
            return 1;
    }

    prober->offset += prober->toa->opsize;

    return 0;
}

static __always_inline bool
__read_toa_2(struct tcphdr *tcp, struct toa_data *toa)
{
    void *buff = (void *) tcp + sizeof(struct tcphdr);
    struct toa_prober prober = {
        .toa = toa,
        .length = (BPF_CORE_READ_BITFIELD_PROBED(tcp, doff) << 2) - sizeof(struct tcphdr),
        .offset = 0,
    };

    /* Tell compiler and verifier that this for loop tries 32 times at most. */
    for (int i = 0; i < MAX_TCPOPT_LEN - sizeof(*toa); i++) {
        int ret = __probe_toa(&prober, buff);
        if (ret < 0)
            return false;
        if (ret > 0)
            return true;
    }

    return false;
}

static __always_inline bool
__read_toa(struct tcphdr *tcp, struct toa_data *toa)
{
    __u8 buff[MAX_TCPOPT_LEN];
    int length;

    length = BPF_CORE_READ_BITFIELD_PROBED(tcp, doff) << 2;
    length -= sizeof(struct tcphdr);

    if (length <= 0)
        return false;

    if (bpf_probe_read_kernel(buff, MAX_TCPOPT_LEN, (void *) tcp + sizeof(struct tcphdr)) < 0)
        return false;

    for (int i = 0; i < MAX_TCPOPT_LEN - sizeof(*toa); ) {
        if (i > length)
            return false;
        barrier_var(i);
        if (i > MAX_TCPOPT_LEN - sizeof(*toa))
            return false;

        __u8 opcode = buff[i];
        if (opcode == TCPOPT_EOL)
            break;
        if (opcode == TCPOPT_NOP) {
            i++;
            continue;
        }

        /* i becomes variable because of i++ */
        /* it's necessary to check range of i again, or
         * invalid variable-offset read from stack R0 var_off=(0x0; 0x1ff) off=-40 size=1
         */
        barrier_var(i);
        if (i + 1 >= MAX_TCPOPT_LEN)
            return false;

        __u8 opsize = buff[i + 1];
        if (opsize < 2)
            return false;

        if ((opcode == TCPOPT_TOA_COMPAT || opcode == TCPOPT_TOA_AKAMAI) && opsize == TCPOLEN_TOA) {
            /* it's necessary to check narrow range of i, or
             * invalid variable-offset read from stack R0 var_off=(0x0; 0x1ff) off=-40 size=1
             */
            barrier_var(i);
            if (i > MAX_TCPOPT_LEN - sizeof(*toa))
                return false;

            /* it fails because of misalign:
             * misaligned stack access off (0x10; 0xf)+-40+0 size 8
             */
            /* *(__u64 *) toa = *(__u64 *) (buff + i); */

            bpf_probe_read_kernel(toa, sizeof(*toa), buff + i);
            return true;
        }

        i += opsize;
    }

    return false;
}

static int
read_toa(struct sk_buff *skb, bool (* fn)(struct tcphdr *, struct toa_data *))
{
    __u16 l4_off = BPF_CORE_READ(skb, transport_header);
    void *skb_head = BPF_CORE_READ(skb, head);
    struct toa_data toa;

    if (fn(skb_head + l4_off, &toa))
        bpf_printk("TOA: opcode=%d, opsize=%d, port=%d, ip=%pI4\n",
                   toa.opcode, toa.opsize, bpf_ntohs(toa.port), &toa.ip);

    return BPF_OK;
}

SEC("fentry/tcp_v4_syn_recv_sock")
int BPF_PROG(toa1, const struct sock *sk, struct sk_buff *skb)
{
    return read_toa(skb, __read_toa);
}

SEC("fentry/tcp_v4_syn_recv_sock")
int BPF_PROG(toa2, const struct sock *sk, struct sk_buff *skb)
{
    return read_toa(skb, __read_toa_2);
}

SEC("fentry/tcp_v4_syn_recv_sock")
int BPF_PROG(toa3, const struct sock *sk, struct sk_buff *skb)
{
    return read_toa(skb, __read_toa_3);
}

SEC("fentry/tcp_v4_syn_recv_sock")
int BPF_PROG(toa4, const struct sock *sk, struct sk_buff *skb)
{
    return read_toa(skb, __read_toa_4);
}
