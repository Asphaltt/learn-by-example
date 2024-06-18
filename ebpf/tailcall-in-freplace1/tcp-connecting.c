//go:build ignore

#include "vmlinux.h"

#include "bpf_all.h"

#include "lib_kprobe.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} socks SEC(".maps");

__noinline int
stub_handler(struct pt_regs *ctx)
{
    bpf_printk("freplace, stub handler, regs: %p\n", ctx);

    return 0;
}

SEC("kprobe/tcp_connect")
int k_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM1(ctx);

    __handle_new_connection(ctx, sk, PROBE_TYPE_DEFAULT, 0);

    u32 key = 0;
    bpf_map_update_elem(&socks, &key, &sk, BPF_ANY);

    stub_handler(ctx);

    return 0;
}

SEC("kprobe/inet_csk_complete_hashdance")
int k_icsk_complete_hashdance(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM2(ctx);

    __handle_new_connection(ctx, sk, PROBE_TYPE_DEFAULT, 0);

    u32 key = 0;
    bpf_map_update_elem(&socks, &key, &sk, BPF_ANY);

    stub_handler(ctx);

    return 0;
}