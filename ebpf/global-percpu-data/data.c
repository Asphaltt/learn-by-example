//go:build ignore

#include "bpf_all.h"

static __u32 happened = 0;
__u32 global_data SEC(".data.percpu") = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
} ringbuf SEC(".maps");

struct event {
    __u32 data;
    __u32 cpu;
};

SEC("fentry/__x64_sys_nanosleep")
int fentry_nanosleep(struct pt_regs *regs)
{
    struct event ev = {};

    if (happened)
        return 0;
    happened = 1;

    global_data++;

    ev.data = global_data;
    ev.cpu = bpf_get_smp_processor_id();

    bpf_ringbuf_output(&ringbuf, &ev, sizeof(ev), BPF_RB_FORCE_WAKEUP);

    return 0;
}