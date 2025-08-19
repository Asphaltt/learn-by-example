//go:build ignore

#include "vmlinux.h"

#include "bpf_all.h"

__u32 run;

SEC("kprobe/tcp_connect")
int k_tcp_connect(struct pt_regs *ctx)
{
    if (run)
        return BPF_OK;
    run = 1;

    return BPF_OK;
}
