//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

static __u32 cnt = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} socks SEC(".maps");

SEC("freplace/stub_handler")
int freplace_handler(struct pt_regs *ctx)
{
    __u32 idx = 0;
    struct sock **skp = (typeof (skp)) bpf_map_lookup_elem(&socks, &idx);
    if (!skp)
        return BPF_OK;

    struct sock *sk = *skp;
    __handle_new_connection(ctx, sk, PROBE_TYPE_FREPLACE, 0);

    if (cnt++ < 50)
        bpf_tail_call_static(ctx, &progs, 0);

    return BPF_OK;
}