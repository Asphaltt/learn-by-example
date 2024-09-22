// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"internal/pkg/bpf"
	"internal/pkg/errx"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang sockops ./sockops.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang sockopsExample ./sockops_example.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	errx.Check(rlimit.RemoveMemlock(), "Failed to remove memlock limit")

	spec, err := loadSockops()
	errx.Check(err, "Failed to load sockops bpf spec")

	var exm sockopsExampleObjects
	err = loadSockopsExampleObjects(&exm, nil)
	errx.Check(err, "Failed to load sockops example bpf objs")

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup/",
		Attach:  ebpf.AttachCGroupSockOps,
		Program: exm.SockopsExample,
	})
	errx.Check(err, "Failed to attach sockops example")
	defer l.Close()

	progs, err := bpf.ListProgs(ebpf.SockOps)
	errx.Check(err, "Failed to list sockops bpf progs")
	defer func() {
		for _, prog := range progs {
			_ = prog.Close()
		}
	}()

	if len(progs) == 0 {
		log.Println("No sockops bpf progs found")
		return
	}

	optionsMap, err := ebpf.NewMap(spec.Maps[".data.options"])
	errx.Check(err, "Failed to create options map")
	defer optionsMap.Close()

	for _, prog := range progs {
		progName, err := bpf.GetProgEntryFuncName(prog)
		errx.Check(err, "Failed to get prog entry func name for prog %v", prog)

		spec := spec.Copy()
		spec.Programs["fentry_sockops"].AttachTarget = prog
		spec.Programs["fentry_sockops"].AttachTo = progName
		spec.Programs["fexit_sockops"].AttachTarget = prog
		spec.Programs["fexit_sockops"].AttachTo = progName

		var objs sockopsObjects
		err = spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				".data.options": optionsMap,
			},
		})
		errx.Check(err, "Failed to load and assign sockops bpf objs")
		defer objs.Close()

		l, err := link.AttachTracing(link.TracingOptions{
			Program:    objs.FentrySockops,
			AttachType: ebpf.AttachTraceFEntry,
		})
		errx.Check(err, "Failed to attach sockops fentry(%s)", progName)
		defer l.Close()
		log.Printf("Attached sockops fentry(%s)", progName)

		l, err = link.AttachTracing(link.TracingOptions{
			Program:    objs.FexitSockops,
			AttachType: ebpf.AttachTraceFExit,
		})
		errx.Check(err, "Failed to attach sockops fexit(%s)", progName)
		defer l.Close()
		log.Printf("Attached sockops fexit(%s)", progName)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()
}
