// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"internal/pkg/bpf"
	"internal/pkg/errx"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/davecgh/go-spew/spew"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang data ./data.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var showInsn bool
	var withoutPercpu bool
	var iface string
	flag.StringVarP(&iface, "iface", "i", "lo", "interface to attach")
	flag.BoolVar(&showInsn, "show-insn", false, "show instructions")
	flag.BoolVar(&withoutPercpu, "without-percpu", false, "without percpu")
	flag.Parse()

	ifi, err := net.InterfaceByName(iface)
	errx.Check(err, "Failed to get interface by name (%s)", iface)

	errx.Check(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if showInsn {
		spec, err := loadData()
		errx.Check(err, "Failed to load bpf spec")

		for i := range spec.Programs["xdp_prog"].Instructions {
			insn := spec.Programs["xdp_prog"].Instructions[i]
			fmt.Printf("%d: %+v\n", i, insn)
			spew.Dump(insn)
		}

		fmt.Println()
	}

	spec, err := loadData()
	errx.Check(err, "Failed to load bpf spec")

	if mapSpec, ok := spec.Maps[".data.__percpu"]; ok && !withoutPercpu {
		log.Printf("Map: %s, contents: %+v", mapSpec.Name, mapSpec.Contents)

		mapSpec.Type = ebpf.PerCPUArray

		value := mapSpec.Contents[0].Value.([]byte)
		values := make([][]byte, runtime.NumCPU())
		for i := range values {
			values[i] = value
		}
		mapSpec.Contents[0].Value = values

		log.Printf("map: %v, contents: %+v", mapSpec, mapSpec.Contents)
	}

	var dataObjs dataObjects
	bpf.LoadWithSpec(spec, &dataObjs)
	defer dataObjs.Close()

	if showInsn {
		prog := dataObjs.XdpProg
		info, err := prog.Info()
		errx.Check(err, "Failed to get xdp prog info")
		insns, err := info.Instructions()
		errx.Check(err, "Failed to get xdp prog instructions")
		for i := range insns {
			insn := insns[i]
			fmt.Printf("%d: %+v\n", i, insn)
			spew.Dump(insn)
		}
		fmt.Println()
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   dataObjs.XdpProg,
		Interface: ifi.Index,
	})
	errx.Check(err, "Failed to attach xdp(%s)", iface)
	defer l.Close()
	log.Printf("Attached xdp(%s)", iface)

	log.Println("Ctrl+C to stop ..")

	<-ctx.Done()
}
