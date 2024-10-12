//go:build ignore
/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

struct guard_spinlock_t {
    struct bpf_spin_lock *lock;
};

void
guard_spinlock_destructor(struct guard_spinlock_t *guard)
{
    bpf_spin_unlock(guard->lock);
}

#define guard_spinlock_constructor(lock)        \
({                                              \
    struct guard_spinlock_t guard = { lock };   \
    bpf_spin_lock(lock);                        \
    guard;                                      \
})

#define __cleanup(fn) __attribute__((cleanup(fn)))

#define guard(lock)                                                     \
    struct guard_spinlock_t var __cleanup(guard_spinlock_destructor) =  \
        guard_spinlock_constructor(lock)

struct xdp_stat_item {
    u64 pkt_cnt;
    u64 pkt_byte;
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct xdp_stat_item);
    __uint(max_entries, 1);
} stats SEC(".maps");

SEC("xdp")
int xdp_fn(struct xdp_md *ctx)
{
    struct ethhdr *eth = (struct ethhdr *)(ctx_ptr(ctx, data));
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct xdp_stat_item *stat;
    u32 key = 0;

    if ((void *)(ip + 1) > ctx_ptr(ctx, data_end))
        return XDP_PASS;

    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    stat = (typeof(stat))bpf_map_lookup_elem(&stats, &key);
    if (stat) {
        guard(&stat->lock);
        stat->pkt_cnt++;
        stat->pkt_byte += (u64)(ctx->data_end - ctx->data);
    }

    return XDP_PASS;
}
