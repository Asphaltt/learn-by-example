/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */
//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 4);
    __uint(max_entries, 100);
} progs SEC(".maps");

SEC("kprobe/tailcall36")
int k_tailcall36(struct pt_regs *ctx)
{
    const int len = 256 - 32;
    volatile char data[len];

    __u32 *n = (__u32 *)&data[0];
    *n = bpf_get_prandom_u32();

    n = (__u32 *)&data[len - 4];
    *n = bpf_get_prandom_u32();

    bpf_printk("tailcall36, stack ptr0: 0x%x, ptrL: 0x%x\n",
        (__u64)(void *)&data[0], (__u64)(void *)&data[len - 1] + 1);

    return 0;
}

static __noinline int __tailcall36(struct pt_regs *ctx)
{
    bpf_tail_call_static(ctx, &progs, 36); // trigger the bug with previous tailcall
    return 0;
}

#define def_tailcall(curr, next)                                         \
    SEC("kprobe/tailcall" #curr)                                         \
    int k_tailcall##curr(struct pt_regs *ctx)                            \
    {                                                                    \
        const int len = 256 - 32;                                        \
        volatile char data[len];                                         \
                                                                         \
        __u32 *n = (__u32 *)&data[0];                                    \
        *n = bpf_get_prandom_u32();                                      \
                                                                         \
        n = (__u32 *)&data[len - 4];                                     \
        *n = bpf_get_prandom_u32();                                      \
                                                                         \
        bpf_printk("tailcall" #curr ", stack ptr0: 0x%x, ptrL: 0x%x\n",  \
            (__u64)(void *)&data[0], (__u64)(void *)&data[len - 1] + 1); \
                                                                         \
        __tailcall##next(ctx);                                           \
                                                                         \
        return 0;                                                        \
    }                                                                    \
                                                                         \
    static __noinline int __tailcall##curr(struct pt_regs *ctx)          \
    {                                                                    \
        bpf_tail_call_static(ctx, &progs, curr);                         \
        return 0;                                                        \
    }

def_tailcall(35, 36);
def_tailcall(34, 35);
def_tailcall(33, 34);
def_tailcall(32, 33);
def_tailcall(31, 32);
def_tailcall(30, 31);
def_tailcall(29, 30);
def_tailcall(28, 29);
def_tailcall(27, 28);
def_tailcall(26, 27);
def_tailcall(25, 26);
def_tailcall(24, 25);
def_tailcall(23, 24);
def_tailcall(22, 23);
def_tailcall(21, 22);
def_tailcall(20, 21);
def_tailcall(19, 20);
def_tailcall(18, 19);
def_tailcall(17, 18);
def_tailcall(16, 17);
def_tailcall(15, 16);
def_tailcall(14, 15);
def_tailcall(13, 14);
def_tailcall(12, 13);
def_tailcall(11, 12);
def_tailcall(10, 11);
def_tailcall(9, 10);
def_tailcall(8, 9);
def_tailcall(7, 8);
def_tailcall(6, 7);
def_tailcall(5, 6);
def_tailcall(4, 5);
def_tailcall(3, 4);
def_tailcall(2, 3);
def_tailcall(1, 2);
def_tailcall(0, 1);

SEC("kprobe/tcp_connect")
int k_tcp_connect(struct pt_regs *ctx)
{
    const int len = 256 - 32;
    volatile char data[len];

    __u32 *n = (__u32 *)&data[0];
    *n = bpf_get_prandom_u32();

    n = (__u32 *)&data[len - 4];
    *n = bpf_get_prandom_u32();

    bpf_printk("tcp_connect, stack ptr0: 0x%x, ptrL: 0x%x\n",
        (__u64)(void *)&data[0], (__u64)(void *)&data[len - 1] + 1);

    __tailcall0(ctx);

    return 0;
}
