//go:build ignore

#include "vmlinux.h"

#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

SEC("freplace/stub_handler")
int freplace_handler()
{
    bpf_printk("freplace, replaced handler\n");

    return 0;
}