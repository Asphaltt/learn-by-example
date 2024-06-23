/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

struct event {
    __u8 cpus[32];
    __u32 cpus_len;
    __u32 ifindex;
    __u64 queue;
    __u64 queue_base;
    __u32 queue_size;
    __u32 pid;
    __u8 is_rps;
    __u8 pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

static __always_inline void
push_event(void *ctx, struct event *event)
{
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
}

static __always_inline void
handle_event(void *ctx, struct event *event, const char *buf, size_t len)
{
    int length = len & (sizeof(event->cpus) - 1);
    bpf_probe_read_kernel(&event->cpus, length, buf);
    event->cpus_len = len;
    event->pid = bpf_get_current_pid_tgid() >> 32;

    push_event(ctx, event);
}

static __always_inline void
get_netdev_rx_queue_index(struct event *event, struct netdev_rx_queue *queue)
{
    struct netdev_rx_queue *_rx = BPF_CORE_READ(queue, dev, _rx);

    event->queue = (__u64)(void *)queue;
    event->queue_base = (__u64)(void *)_rx;
    event->queue_size = sizeof(*queue);
}

SEC("fexit/store_rps_map")
int BPF_PROG(fexit_store_rps_map, struct netdev_rx_queue *queue,
             const char *buf, size_t len, ssize_t ret)
{
    struct event event = {
        .is_rps = 1,
    };

    if (ret < 0)
        return BPF_OK;

    BPF_CORE_READ_INTO(&event.ifindex, queue, dev, ifindex);
    get_netdev_rx_queue_index(&event, queue);

    handle_event(ctx, &event, buf, len);

    return BPF_OK;
}

static __always_inline void
get_netdev_tx_queue_index(struct event *event, struct netdev_queue *queue)
{
    struct netdev_queue *_tx = BPF_CORE_READ(queue, dev, _tx);

    event->queue = (__u64)(void *)queue;
    event->queue_base = (__u64)(void *)_tx;
    event->queue_size = sizeof(*queue);
}

SEC("fexit/xps_cpus_store")
int BPF_PROG(fexit_xps_cpus_store, struct netdev_queue *queue,
             const char *buf, size_t len, ssize_t ret)
{
    struct event event = {
        .is_rps = 0,
    };

    if (ret < 0)
        return BPF_OK;

    BPF_CORE_READ_INTO(&event.ifindex, queue, dev, ifindex);
    get_netdev_tx_queue_index(&event, queue);

    handle_event(ctx, &event, buf, len);

    return BPF_OK;
}