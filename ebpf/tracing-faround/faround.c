//go:build ignore

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "GPL";

int count = 0;

SEC("fexit/tcp_connect")
int BPF_PROG(faround__tcp_connect)
{
    count++;
    return 0;
}
