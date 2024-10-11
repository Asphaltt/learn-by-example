// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"internal/pkg/errx"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp ./xdp.c -- -g -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang freplace ./freplace.c -- -g -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var length int
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach XDP program")
	flag.IntVarP(&length, "length", "l", 10, "length of the chain")
	flag.Parse()

	if length < 1 {
		log.Fatalf("length should be greater than 0")
	}

	ifi := errx.Must(netlink.LinkByName(device))

	errx.Check(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadXdp()
	errx.Check(err, "Failed to load xdp bpf spec")

	bssMap, err := ebpf.NewMap(spec.Maps[".bss"])
	errx.Check(err, "Failed to create data map")
	defer bssMap.Close()

	defer func() {
		var count uint32
		err := bssMap.Lookup(uint32(0), &count)
		errx.Check(err, "Failed to lookup count")
		fmt.Println()
		log.Printf("Final count: %d", count)
	}()

	var xdpFirst *ebpf.Program
	var jmpTable *ebpf.Map
	for i := 0; i < length; i++ {
		var xdpObjs xdpObjects
		errx.CheckVerifierErr(loadXdpObjects(&xdpObjs, &ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				".bss": bssMap,
			},
		}), "Failed to load xdp objects")
		defer xdpObjs.Close()
		if xdpFirst == nil {
			xdpFirst = xdpObjs.XdpFn
		}

		spec, err := loadFreplace()
		errx.Check(err, "Failed to load freplace bpf spec")
		spec.Programs["freplace_fn"].AttachTarget = xdpObjs.XdpFn
		spec.Programs["freplace_fn"].AttachTo = "xdp_subprog"

		var frObjs freplaceObjects
		errx.CheckVerifierErr(spec.LoadAndAssign(&frObjs, nil), "Failed to load freplace objects")
		defer frObjs.Close()

		l, err := link.AttachFreplace(xdpObjs.XdpFn, "xdp_subprog", frObjs.FreplaceFn)
		errx.Check(err, "Failed to attach freplace")
		defer l.Close()

		if jmpTable != nil {
			errx.Check(jmpTable.Put(uint32(0), xdpObjs.XdpFn), "Failed to put xdp program to jmp table")
		}
		jmpTable = frObjs.JmpTable
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpFirst,
		Interface: ifi.Attrs().Index,
	})
	errx.Check(err, "Failed to attach xdp(%s)", device)
	defer l.Close()

	log.Printf("Attached xdp to %s", device)

	<-ctx.Done()
}
