/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

#define NETCONFA_IFINDEX_ALL        -1
#define NETCONFA_IFINDEX_DEFAULT    -2

struct event {
    __u8 comm[32];
    __u32 pad;
    __u32 pid;
    __s32 ifindex;
    __s32 devconf_value;
    __u64 cnf_data_ptr;
    __u64 ctl_data_ptr;
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
handle_event(void *ctx, struct event *event)
{
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    push_event(ctx, event);
}

static __always_inline int
devinet_conf_ifindex(struct net *net, struct ipv4_devconf *cnf)
{
    if (cnf == BPF_CORE_READ(net, ipv4.devconf_dflt))
        return NETCONFA_IFINDEX_DEFAULT;
    else if (cnf == BPF_CORE_READ(net, ipv4.devconf_all))
        return NETCONFA_IFINDEX_ALL;
    else {
        struct in_device *idev
            = container_of(cnf, struct in_device, cnf);
        return BPF_CORE_READ(idev, dev, ifindex);
    }
}

static __always_inline int
__fexit(void *ctx, struct ctl_table *ctl, int write, void *buffer, size_t *lenp,
        loff_t *ppos, int retval)
{
    struct ipv4_devconf *cnf;
    struct event event = {};
    struct net *net;

    if (retval || !write)
        return BPF_OK;

    // Only interested in writing devinet conf.

    cnf = (typeof(cnf)) BPF_CORE_READ(ctl, extra1);
    net = (typeof(net)) BPF_CORE_READ(ctl, extra2);

    event.ifindex = devinet_conf_ifindex(net, cnf);
    event.cnf_data_ptr = ((__u64) cnf) + offsetof(struct ipv4_devconf, data);
    event.ctl_data_ptr = (__u64) BPF_CORE_READ(ctl, data);
    bpf_probe_read_kernel(&event.devconf_value, sizeof(event.devconf_value),
                          BPF_CORE_READ(ctl, data));

    handle_event(ctx, &event);

    return BPF_OK;
}

SEC("fexit/devinet_conf_proc")
int BPF_PROG(fexit_devinet_conf_proc, struct ctl_table *ctl, int write,
             void *buffer, size_t *lenp, loff_t *ppos, int retval)
{
    return __fexit(ctx, ctl, write, buffer, lenp, ppos, retval);
}

SEC("fexit/ipv4_doint_and_flush")
int BPF_PROG(fexit_ipv4_doint_and_flush, struct ctl_table *ctl, int write,
             void *buffer, size_t *lenp, loff_t *ppos, int retval)
{
    return __fexit(ctx, ctl, write, buffer, lenp, ppos, retval);
}

SEC("fexit/devinet_sysctl_forward")
int BPF_PROG(fexit_devinet_sysctl_forward, struct ctl_table *ctl, int write,
             void *buffer, size_t *lenp, loff_t *ppos, int retval)
{
    return __fexit(ctx, ctl, write, buffer, lenp, ppos, retval);
}