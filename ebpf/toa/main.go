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

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang toa ./toa.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	errx.Check(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var objs toaObjects
	errx.CheckVerifierErr(loadToaObjects(&objs, nil), "Failed to load toa objects")
	defer objs.Close()

	l, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FentryTcpV4SynRecvSock,
	})
	errx.Check(err, "Failed to attach fexit(tcp_v4_syn_recv_sock)")
	defer l.Close()
	log.Println("Attached fexit(tcp_v4_syn_recv_sock)")

	log.Println("Check TOA by `cat /sys/kernel/debug/tracing/trace_pipe` ..")

	<-ctx.Done()
}
