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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang faround ./faround.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove memlock rlimit: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadFaround()
	assert.NoErr(err, "Failed to load BPF program: %v")

	spec.Programs["faround__tcp_connect"].AttachType = link.AttachTraceFAround

	coll, err := ebpf.NewCollection(spec)
	assert.NoErr(err, "Failed to create BPF collection: %v")
	defer coll.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program:    coll.Programs["faround__tcp_connect"],
		AttachType: link.AttachTraceFAround,
	})
	assert.NoErr(err, "Failed to attach tracing program: %v")
	defer link.Close()
	log.Printf("Attached faround(tcp_connect)")

	<-ctx.Done()

	var c uint32
	cnt := coll.Variables["count"]
	err = cnt.Get(&c)
	assert.NoErr(err, "Failed to get count variable: %v")
	log.Printf("Count: %d", c)
}
