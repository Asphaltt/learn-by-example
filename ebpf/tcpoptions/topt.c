/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

static volatile const __u8 TARGET_OPCODE = 0;
static volatile const __u8 TARGET_OPVAL[36] = { 0 };
static volatile const __u32 TARGET_OPVAL_LEN = 0; // including the suffix '\0'

/* Copied from include/net/tcp.h:
 *  TCP option
 */

#define TCPOPT_NOP                      1   /* Padding */
#define TCPOPT_EOL                      0   /* End of options */
#define TCPOPT_MSS                      2   /* Segment size negotiating */
#define TCPOPT_WINDOW                   3   /* Window scaling */
#define TCPOPT_SACK_PERM                4   /* SACK Permitted */
#define TCPOPT_SACK                     5   /* SACK Block */
#define TCPOPT_TIMESTAMP                8   /* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG                   19  /* MD5 Signature (RFC2385) */
#define TCPOPT_AO                       29  /* Authentication Option (RFC5925) */
#define TCPOPT_MPTCP                    30  /* Multipath TCP (RFC6824) */
#define TCPOPT_FASTOPEN                 34  /* Fast open (RFC7413) */
#define TCPOPT_TOA_AKAMAI               253
#define TCPOPT_TOA_COMPAT               254

/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS                     4
#define TCPOLEN_WINDOW                  3
#define TCPOLEN_SACK_PERM               2
#define TCPOLEN_TIMESTAMP               10
#define TCPOLEN_MD5SIG                  18
#define TCPOLEN_FASTOPEN_BASE           2
#define TCPOLEN_EXP_FASTOPEN_BASE       4
#define TCPOLEN_EXP_SMC_BASE            6

/* But this is what stacks really send out. */
#define TCPOLEN_TSTAMP_ALIGNED          12
#define TCPOLEN_WSCALE_ALIGNED          4
#define TCPOLEN_SACKPERM_ALIGNED        4
#define TCPOLEN_SACK_BASE               2
#define TCPOLEN_SACK_BASE_ALIGNED       4
#define TCPOLEN_SACK_PERBLOCK           8
#define TCPOLEN_MD5SIG_ALIGNED          20
#define TCPOLEN_MSS_ALIGNED             4
#define TCPOLEN_EXP_SMC_BASE_ALIGNED    8

#define TCPOLEN_MARK                    255

struct tcp_option {
    __u8 opsize;
    char opname[35];
} __attribute__((packed)) tcp_options[] = {
    [TCPOPT_MSS]        = { TCPOLEN_MSS,        "MSS" },                                /* 2 */
    [TCPOPT_WINDOW]     = { TCPOLEN_WINDOW,     "Window Scale" },                       /* 3 */
    [TCPOPT_SACK_PERM]  = { TCPOLEN_SACK_PERM,  "SACK Permitted" },                     /* 4 */
    [TCPOPT_SACK]       = { TCPOLEN_MARK,       "SACK" },                               /* 5 */
    [6]                 = { 6,                  "Echo" },                               /* 6 */
    [7]                 = { 6,                  "Echo Reply" },                         /* 7 */
    [TCPOPT_TIMESTAMP]  = { TCPOLEN_TIMESTAMP,  "Timestamp" },                          /* 8 */
    [9]                 = { 2,                  "Partial Order Connection Permitted" }, /* 9 */
    [10]                = { 3,                  "Partial Order Service Profile" },      /* 10 */
    [14]                = { 3,                  "TCP Alternate Checksum Request" },     /* 14 */
    [15]                = { TCPOLEN_MARK,       "TCP Alternate Checksum Data" },        /* 15 */
    [18]                = { 3,                  "Trailer Checksum Option" },            /* 18 */
    [TCPOPT_MD5SIG]     = { TCPOLEN_MD5SIG,     "MD5 Signature Option" },               /* 19 */
    [27]                = { 8,                  "Quick-Start Response" },               /* 27 */
    [28]                = { 4,                  "User Timeout Option" },                /* 28 */
    [30]                = { TCPOLEN_MARK,       "Multipath TCP (MPTCP)" },              /* 30 */
    [34]                = { TCPOLEN_MARK,       "TCP Fast Open Cookie" },               /* 34 */
    [69]                = { TCPOLEN_MARK,       "Encryption Negotiation (TCP-ENO)" },   /* 69 */
    [172]               = { TCPOLEN_MARK,       "Acceptable ECN Order 0" },             /* 172 */
    [174]               = { TCPOLEN_MARK,       "Acceptable ECN Order 1" },             /* 174 */
    [253]               = { 8,                  "TOA" },                                /* 253 */
    [254]               = { 8,                  "TOA" },                                /* 254 */
    [255]               = {},                                                           /* 255 */
};

struct toa_data {
	__u8 opcode;
	__u8 opsize;
	__u16 port;
	__u32 ip;
};

static __always_inline bool
__check(void *data, void *data_end, int length)
{
    return data + length <= data_end;
}

static __noinline void
modify_option(void *data, void *data_end, __u8 opsize)
{
    int offset = 0;

#define CHECK_SIZE(size) \
    offset + size <= sizeof(TARGET_OPVAL) && offset + size <= opsize && offset + size <= TARGET_OPVAL_LEN

    for ( ; CHECK_SIZE(8); ) {
        if (!__check(data, data_end, 8))
            return;

        *(__u64 *) data = *(__u64 *) &TARGET_OPVAL[offset];
        offset += 8;
    }

    if (CHECK_SIZE(4)) {
        if (!__check(data, data_end, 4))
            return;

        *(__u32 *) data = *(__u32 *) &TARGET_OPVAL[offset];
        offset += 4;
    }

    if (CHECK_SIZE(2)) {
        if (!__check(data, data_end, 2))
            return;

        *(__u16 *) data = *(__u16 *) &TARGET_OPVAL[offset];
        offset += 2;
    }

    if (CHECK_SIZE(1)) {
        if (!__check(data, data_end, 1))
            return;

        *(__u8 *) data = TARGET_OPVAL[offset];
    }

#undef CHECK_SIZE
}

static int
parse_option(struct xdp_md *xdp, __u8 offset)
{
    void *data_end = ctx_ptr(xdp, data_end);
    void *data = ctx_ptr(xdp, data);
    struct tcp_option *topt;
    __u8 opcode, opsize;

    /* offset &= 255; */ /* r2 &= 255 is applied by int to __u8 automatically */
    data += offset;
    if (!__check(data, data_end, 1))
        return -1;

    opcode = *(__u8 *) data;
    data++;

    switch (opcode) {
    case TCPOPT_EOL: /* 0 */
        return -1;

    case TCPOPT_NOP: /* 1 */
        return 1;
    }

    if (!__check(data, data_end, 1))
        return -1;

    opsize = *(__u8 *) data;
    data++;

    if (opsize < 2)
        return -1;

    if (opcode == TCPOPT_TOA_AKAMAI || opcode == TCPOPT_TOA_COMPAT) {
        if (opsize == 8) {
            if (!__check(data, data_end, 6))
                return -1;

            struct toa_data *toa = (struct toa_data *) (data - 2);
            bpf_printk("topts: TOA: port=%d ip=%pI4\n", bpf_ntohs(toa->port), &toa->ip);
            return 8;
        }
    }

    topt = &tcp_options[opcode];
    if (topt->opsize == 0) {
        bpf_printk("topts: unknown opcode(%d)\n", opcode);
    } else if (topt->opsize != TCPOLEN_MARK && opsize != topt->opsize) {
        bpf_printk("topts: %s: invalid opsize(%d), exp opsize(%d)\n",
                   topt->opname, opsize, topt->opsize);
    }

    switch (opsize) {
    case 2:
        if (topt->opname[0] != '\0')
            bpf_printk("topts: %s: opsize(%d)\n", topt->opname, opsize);
        break;

    case 2+1:
        if (__check(data, data_end, 1))
            bpf_printk("topts: %s: opsize(%d), val: %d\n",
                       topt->opname, opsize, *(__u8 *) data);
        break;

    case 2+2:
        if (__check(data, data_end, 2))
            bpf_printk("topts: %s: opsize(%d), val: 0x%x\n",
                       topt->opname, opsize, bpf_ntohs(*(__u16 *) data));
        break;

    case 2+4:
        if (__check(data, data_end, 4))
            bpf_printk("topts: %s: opsize(%d), val: 0x%x\n",
                       topt->opname, opsize, bpf_ntohl(*(__u32 *) data));
        break;

    case 2+8:
        if (__check(data, data_end, 8))
            bpf_printk("topts: %s: opsize(%d), val: 0x%llx\n",
                       topt->opname, opsize, bpf_be64_to_cpu(*(__u64 *) data));
        break;
    }

    if (opcode == TARGET_OPCODE)
        modify_option(data, data_end, opsize-2);

    return opsize;
}

SEC("freplace/option_parser")
int topt(struct xdp_md *xdp, int offset)
{
    return parse_option(xdp, offset);
}
