//go:build ignore
#include "vmlinux.h"

#include "bpf_helpers.h"

unsigned long bpf_ffs64(u64 word) __ksym;

static __noinline __u64
__ffs64(__u64 word)
{
    __u64 shift = 0;
    if ((word & 0xffffffff) == 0) {
        word >>= 32;
        shift += 32;
    }
    if ((word & 0xffff) == 0) {
        word >>= 16;
        shift += 16;
    }
    if ((word & 0xff) == 0) {
        word >>= 8;
        shift += 8;
    }
    if ((word & 0xf) == 0) {
        word >>= 4;
        shift += 4;
    }
    if ((word & 0x3) == 0) {
        word >>= 2;
        shift += 2;
    }
    if ((word & 0x1) == 0) {
        shift += 1;
    }

    return shift;
}

SEC("tc")
int tc_ffs1(struct __sk_buff *skb)
{
    void *data_end = (void *)(long) skb->data_end;
    u64 *data = (u64 *)(long) skb->data;

    if ((void *)(u64) (data + 1) > data_end)
        return 0;

    return __ffs64(*data);
}

SEC("tc")
int tc_ffs2(struct __sk_buff *skb)
{
    void *data_end = (void *)(long) skb->data_end;
    u64 *data = (u64 *)(long) skb->data;

    if ((void *)(u64) (data + 1) > data_end)
        return 0;

    return bpf_ffs64(*data);
}

char _license[] SEC("license") = "GPL";
