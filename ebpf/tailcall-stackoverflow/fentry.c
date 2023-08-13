/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */
//go:build ignore

#include "bpf_all.h"

#define def_fentry_tailcall(curr)                                               \
    SEC("fentry/__tailcall" #curr)                                              \
    int BPF_PROG(fentry__tailcall##curr, struct pt_regs *regs)                  \
    {                                                                           \
        const int len = 256 - 32;                                               \
        volatile char data[len];                                                \
                                                                                \
        __u32 *n = (__u32 *)&data[0];                                           \
        *n = bpf_get_prandom_u32();                                             \
                                                                                \
        n = (__u32 *)&data[len - 4];                                            \
        *n = bpf_get_prandom_u32();                                             \
                                                                                \
        bpf_printk("fentry__tailcall" #curr ", stack ptr0: 0x%x, ptrL: 0x%x\n", \
            (__u64)(void *)&data[0], (__u64)(void *)&data[len - 1] + 1);        \
                                                                                \
        return 0;                                                               \
    }

def_fentry_tailcall(0);
def_fentry_tailcall(1);
def_fentry_tailcall(2);
def_fentry_tailcall(3);
def_fentry_tailcall(4);
def_fentry_tailcall(5);
def_fentry_tailcall(6);
def_fentry_tailcall(7);
def_fentry_tailcall(8);
def_fentry_tailcall(9);
def_fentry_tailcall(10);
def_fentry_tailcall(11);
def_fentry_tailcall(12);
def_fentry_tailcall(13);
def_fentry_tailcall(14);
def_fentry_tailcall(15);
def_fentry_tailcall(16);
def_fentry_tailcall(17);
def_fentry_tailcall(18);
def_fentry_tailcall(19);
def_fentry_tailcall(20);
def_fentry_tailcall(21);
def_fentry_tailcall(22);
def_fentry_tailcall(23);
def_fentry_tailcall(24);
def_fentry_tailcall(25);
def_fentry_tailcall(26);
def_fentry_tailcall(27);
def_fentry_tailcall(28);
def_fentry_tailcall(29);
def_fentry_tailcall(30);
def_fentry_tailcall(31);
def_fentry_tailcall(32);
def_fentry_tailcall(33);
def_fentry_tailcall(34);
def_fentry_tailcall(35);