// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tp_btf ./tp_btf.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fentry ./fentry.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var obj tp_btfObjects
	assert.NoVerifierErr(loadTp_btfObjects(&obj, nil), "Failed to load bpf spec: %v")
	defer obj.Close()

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    obj.TpBtfNetifReceiveSkb,
		AttachType: ebpf.AttachTraceRawTp,
	})
	assert.NoErr(err, "Failed to attach tracing: %v")
	defer l.Close()

	// var fobj fentryObjects
	// assert.NoVerifierErr(loadFentryObjects(&fobj, nil), "Failed to load bpf spec: %v")
	// defer fobj.Close()

	log.Println("Press CTRL+C to stop")

	<-ctx.Done()
}
