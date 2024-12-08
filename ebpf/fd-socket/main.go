// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"internal/pkg/errx"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcp ./tcp.c -- -g -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	errx.Check(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock: %v")

	spec, err := loadTcp()
	errx.Check(err, "Failed to load tcp bpf spec: %v")

	coll, err := ebpf.NewCollection(spec)
	errx.CheckVerifierErr(err, "Failed to load tcp bpf spec: %v")
	defer coll.Close()

	for name, prog := range coll.Programs {
		if name == "tp_inet_sock_set_state" {
			continue
		}

		l, err := link.AttachTracing(link.TracingOptions{
			Program: prog,
		})
		errx.Check(err, "Failed to attach tracing(%s): %v", name)
		defer l.Close()
	}

	tp, err := link.Tracepoint("sock", "inet_sock_set_state",
		coll.Programs["tp_inet_sock_set_state"], &link.TracepointOptions{})
	errx.Check(err, "Failed to attach tracepoint(inet_sock_set_state): %v")
	defer tp.Close()

	log.Print("fd-socket is running. Press Ctrl+C to stop")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
}
