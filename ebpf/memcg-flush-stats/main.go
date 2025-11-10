// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"internal/assert"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang memcg ./memcg.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadMemcg()
	assert.NoErr(err, "Failed to load bpf obj: %v")

	coll, err := ebpf.NewCollection(spec)
	assert.NoVerifierErr(err, "Failed to create bpf collection: %v")
	defer coll.Close()

	funcName := "memory_stat_show"

	prog := coll.Programs[funcName]
	link, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	assert.NoErr(err, "Failed to attach fentry: %v", err)
	defer link.Close()

	log.Print("Attached! Press Ctrl+C to exit.")

	<-ctx.Done()
}
