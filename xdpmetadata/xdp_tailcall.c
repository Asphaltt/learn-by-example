//go:build ignore

#include "vmlinux.h"

#include "bpf_helpers.h"

#define MAGIC 0xFEDCBA98

#define ctx_ptr(ctx, mem) (void *)(unsigned long)ctx->mem

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} xdp_progs SEC(".maps");

SEC("xdp")
int xdp_fn(struct xdp_md *ctx)
{
    __u32 *val;

    // Note: do not bpf_xdp_adjust_meta again.

    void *data_meta = ctx_ptr(ctx, data_meta);
    void *data = ctx_ptr(ctx, data);

    val = (typeof(val))data_meta;
    if ((void *)(val + 1) > data)
        return XDP_PASS;

    if (*val == MAGIC)
        bpf_printk("xdp tailcall\n");

    return XDP_PASS;
}

SEC("xdp")
int xdp_tailcall(struct xdp_md *ctx)
{
    __u32 *val;
    const int siz = sizeof(*val);

    if (bpf_xdp_adjust_meta(ctx, -siz) != 0)
        return XDP_PASS;

    void *data_meta = ctx_ptr(ctx, data_meta);
    void *data = ctx_ptr(ctx, data);

    val = (typeof(val))data_meta;
    if ((void *)(val + 1) > data)
        return XDP_PASS;

    *val = MAGIC;
    bpf_printk("xdp metadata\n");

    bpf_tail_call_static(ctx, &xdp_progs, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
