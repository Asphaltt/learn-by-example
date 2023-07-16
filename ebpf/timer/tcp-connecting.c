//go:build ignore
#include "bpf_all.h"

struct sk_key {
    __be32 saddr, daddr;
    __be16 sport, dport;
};

struct tcp_timer {
    struct bpf_timer timer;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, struct sk_key);
    __type(value, struct tcp_timer);
} tcp_timers SEC(".maps");

static int
timer_cb(struct bpf_map *map, struct sk_key *key, struct tcp_timer *timer)
{
    bpf_printk("timer_cb, new connection 0x%x -> 0x%x\n", key->saddr, key->daddr);
    return 0;
}

static __noinline void
handle_new_connection(void *ctx, struct sock *sk)
{
    struct sk_key key = {};

    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_printk("handle_new_connection, new connection 0x%x -> 0x%x\n", key.saddr, key.daddr);

    struct tcp_timer init_timer = {};
    struct tcp_timer *timer = bpf_map_lookup_or_try_init(&tcp_timers, &key, &init_timer);
    if (!timer) {
        bpf_printk("handle_new_connection, failed to lookup timer from bpf map\n");
        return;
    }

    int ret;
    ret = bpf_timer_init(&timer->timer, &tcp_timers, CLOCK_BOOTTIME);
    if (ret) {
        bpf_printk("handle_new_connection, failed to init timer: %d\n", ret);
        return;
    }

    ret = bpf_timer_set_callback(&timer->timer, timer_cb);
    if (ret) {
        bpf_printk("handle_new_connection, failed to set timer callback: %d\n", ret);
        return;
    }

    ret = bpf_timer_start(&timer->timer, 100, 0);
    if (ret) {
        bpf_printk("handle_new_connection, failed to start timer: %d\n", ret);
        return;
    }
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