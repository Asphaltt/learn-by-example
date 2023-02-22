//go:build ignore

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "GPL";

typedef struct event {
    __be32 saddr, daddr;
    __be16 sport, dport;
} __attribute__((packed)) event_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

static __noinline void handle_new_connection(void *ctx, struct sock *sk)
{
    event_t ev = {};

    ev.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ev.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
}

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk)
{
    handle_new_connection(ctx, sk);

    return 0;
}

SEC("fexit/inet_csk_complete_hashdance")
int BPF_PROG(inet_csk_complete_hashdance, struct sock *sk, struct sock *child,
    struct request_sock *req, bool own_req, struct sock *ret)
{
    if (ret)
        handle_new_connection(ctx, ret);

    return 0;
}