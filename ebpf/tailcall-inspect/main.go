// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"internal/pkg/errx"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tailcall ./tailcall.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var progID uint
	var myInspectFuncName string
	flag.UintVar(&progID, "prog", 0, "ID of the BPF program to inspect")
	flag.StringVar(&myInspectFuncName, "func", "my_tailcall_inspect", "name of the function to inspect")
	flag.Parse()

	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	errx.Check(err, "Failed to load bpf prog")
	defer prog.Close()

	spec, err := loadTailcall()
	errx.Check(err, "Failed to load bpf spec")

	progName := "tailcall_inspect"
	progSpec := spec.Programs[progName]
	progSpec.AttachTarget = prog
	progSpec.AttachTo = myInspectFuncName
	progSpec.AttachType = ebpf.AttachTraceFEntry

	coll, err := ebpf.NewCollection(spec)
	errx.CheckVerifierErr(err, "Failed to create bpf collection")
	defer coll.Close()

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    coll.Programs[progName],
		AttachType: ebpf.AttachTraceFEntry,
	})
	errx.Check(err, "Failed to attach bpf program")
	defer l.Close()

	log.Printf("Tracing %s ..", myInspectFuncName)
	log.Printf("cat /sys/kernel/debug/tracing/trace_pipe to see the output")
	log.Printf("Press Ctrl+C to stop")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()
}
