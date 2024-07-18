//go:build ignore

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "GPL";

static __noinline int
stub_handler_static()
{
    bpf_printk("freplace, stub handler static\n");

    return 0;
}

__noinline int
stub_handler()
{
    bpf_printk("freplace, stub handler\n");

    return 0;
}

typedef struct event {
    __be32 saddr, daddr;
    __be16 sport, dport;
} __attribute__((packed)) event_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

static __noinline
void handle_new_connection(struct pt_regs *ctx, struct sock *sk)
{
    event_t ev = {};

    ev.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ev.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
}

SEC("kprobe/tcp_connect")
int k_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM1(ctx);

    handle_new_connection(ctx, sk);

    stub_handler_static();

    return stub_handler();
}

SEC("kprobe/inet_csk_complete_hashdance")
int k_icsk_complete_hashdance(struct pt_regs *ctx)
{
    struct sock *sk;
    sk = (typeof(sk))PT_REGS_PARM2(ctx);

    handle_new_connection(ctx, sk);

    stub_handler_static();

    return stub_handler();
}