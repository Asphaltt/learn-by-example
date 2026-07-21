/**
 * Copyright 2026 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bpf_all.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

SEC("fentry")
int BPF_PROG(chain_fentry)
{
	bpf_tail_call_static(ctx, &jmp_table, 0);
	return BPF_OK;
}

static __noinline int subprog(void *ctx)
{
	__sink(ctx);
	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(main1)
{
	subprog(ctx);
	return BPF_OK;
}
