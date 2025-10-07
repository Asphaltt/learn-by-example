// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"internal/pkg/errx"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fentry ./fentry.c -- -g -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	errx.Check(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock: %v")

	btfs, err := btf.LoadKernelSpec()
	errx.Check(err, "Failed to load BTF spec: %v")

	typ, err := btfs.AnyTypeByName("sk_buff")
	errx.Check(err, "Failed to find sk_buff type: %v")

	typeID, err := btfs.TypeID(typ)
	errx.Check(err, "Failed to get sk_buff type ID: %v")
	log.Printf("sk_buff type ID: %d", typeID)

	spec, err := loadFentry()
	errx.Check(err, "Failed to load fentry bpf spec: %v")

	err = spec.Variables["btf_id"].Set(uint32(typeID))
	errx.Check(err, "Failed to set btf_id variable: %v")

	coll, err := ebpf.NewCollection(spec)
	errx.CheckVerifierErr(err, "Failed to load fentry bpf spec: %v")
	defer coll.Close()

	l, err := link.AttachTracing(link.TracingOptions{
		Program: coll.Programs["fentry_icmp_rcv"],
	})
	errx.Check(err, "Failed to attach fentry program: %v")
	defer l.Close()

	log.Println("eBPF fentry program loaded and attached. Press Ctrl+C to exit.")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
}
