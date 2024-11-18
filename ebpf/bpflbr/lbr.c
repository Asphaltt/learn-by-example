//go:build ignore

#include "bpf_all.h"

#include "bpf_cleanup.h"

#define MAX_LBR_ENTRIES 32

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

struct event {
    struct perf_branch_entry lbr[MAX_LBR_ENTRIES];
    __s64 nr_bytes;
    __s64 retval;
} __attribute__((packed));

SEC("fexit")
int BPF_PROG(fexit_fn)
{
    struct event *event;
    int err = 0;

    guard_ringbuf(&events, event, &err);
    if (!event)
        return BPF_OK;

    event->nr_bytes = bpf_get_branch_snapshot(event->lbr, sizeof(event->lbr), 0); /* 5.16 */
    bpf_get_func_ret(ctx, &event->retval); /* 5.17 */

    return BPF_OK;
}
