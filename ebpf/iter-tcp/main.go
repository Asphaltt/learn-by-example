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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang iter ./iter.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadIter()
	assert.NoErr(err, "Failed to load bpf obj: %v")

	coll, err := ebpf.NewCollection(spec)
	assert.NoVerifierErr(err, "Failed to create bpf collection: %v")
	defer coll.Close()

	funcName := "iter_tcp"
	link, err := link.AttachIter(link.IterOptions{
		Program: coll.Programs[funcName],
	})
	assert.NoErr(err, "Failed to attach iter: %v")
	defer link.Close()

	err = link.Pin("/sys/fs/bpf/itertcp")
	assert.NoErr(err, "Failed to pin iter: %v")
	defer link.Unpin()

	log.Printf("cat /sys/fs/bpf/itertcp to check tcp connections")

	log.Printf("Attached iter")

	log.Print("Attached! Press Ctrl+C to exit.")

	<-ctx.Done()
}
