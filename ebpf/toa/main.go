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
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang toa ./toa.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var way string
	flag.StringVarP(&way, "way", "w", "1", "use toa way 1, 2 or 3")
	flag.Parse()

	errx.Check(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var objs toaObjects
	errx.CheckVerifierErr(loadToaObjects(&objs, nil), "Failed to load toa objects")
	defer objs.Close()

	var prog *ebpf.Program
	switch way {
	case "1":
		prog = objs.Toa1
	case "2":
		prog = objs.Toa2
	case "3":
		prog = objs.Toa3
	case "4":
		prog = objs.Toa4
	default:
		log.Fatalf("Invalid way: %s", way)
	}

	l, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	errx.Check(err, "Failed to attach fexit(tcp_v4_syn_recv_sock)")
	defer l.Close()
	log.Println("Attached fexit(tcp_v4_syn_recv_sock)")

	log.Println("Check TOA by `cat /sys/kernel/debug/tracing/trace_pipe` ..")

	<-ctx.Done()
}
