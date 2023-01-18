#ifndef __BPF_CSUM_H_
#define __BPF_CSUM_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

static __always_inline __u16 csum_fold_helper(__wsum sum)
{
    sum = (sum & 0xffff) + (sum >> 16);
    return ~((sum & 0xffff) + (sum >> 16));
}

/*
 * Use like `icmph->checksum = ipv4_csum(icmph, ICMP_ECHO_LEN);`
 */
static __always_inline __u16 ipv4_csum(void *data_start, int data_size)
{
    __wsum sum = 0;
    sum = bpf_csum_diff(0, 0, data_start, data_size, 0);
    return csum_fold_helper(sum);
}

#endif // __BPF_CSUM_H_