// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"internal/assert"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate bpf2go -cc clang kptr ./kptr.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

/*
 * kptr_bpfel.o: load relocations: section "fentry/__x64_sys_nanosleep": reference to "lock" in section SHN_UNDEF+7: not supported
 */

func main() {
	err := rlimit.RemoveMemlock()
	assert.NoErr(err, "Failed to remove rlimit memlock: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
}
