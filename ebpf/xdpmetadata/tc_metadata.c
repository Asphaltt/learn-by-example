//go:build ignore

#include "vmlinux.h"

#include "bpf_helpers.h"

#include "bpf_tc.h"

#define MAGIC 0xFEDCBA98

#define ctx_ptr(ctx, mem) (void *)(unsigned long)ctx->mem


SEC("tc")
int tc_metadata(struct __sk_buff *skb)
{
    void *data = ctx_ptr(skb, data);
    void *data_meta = ctx_ptr(skb, data_meta);

    __u32 *val;
    val = (typeof(val))data_meta;

    if ((void *)(val +1) > data)
        return TC_ACT_OK;

    if (*val == MAGIC)
        bpf_printk("tc metadata\n");

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
