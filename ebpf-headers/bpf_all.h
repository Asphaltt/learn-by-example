#ifndef __BPF_ALL_H_
#define __BPF_ALL_H_

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"
#include "bpf_tc.h"
#include "bpf_tracing.h"

#include "if_ether.h"
#include "icmp.h"
#include "bpf_csum.h"

#define ctx_ptr(ctx, mem) (void *)(unsigned long)ctx->mem

char _license[] SEC("license") = "GPL";


#endif // __BPF_ALL_H_