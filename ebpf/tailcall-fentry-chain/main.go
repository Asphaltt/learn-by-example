// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"internal/assert"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang chain ./chain.c -- -D__TARGET_ARCH_x86 -I../headers -Wall -g

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove memlock: %v")

	spec, err := loadChain()
	assert.NoErr(err, "Failed to load spec: %v")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	<-ctx.Done()
}
