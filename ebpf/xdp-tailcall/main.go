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
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp ./xdp.c -- -g -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang freplace ./freplace.c -- -g -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach XDP program")
	flag.Parse()

	ifi := errx.Must(netlink.LinkByName(device))

	errx.Check(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var xdpFirst *ebpf.Program
	var jmpTable *ebpf.Map
	for i := 0; i < 100000; i++ {
		var xdpObjs xdpObjects
		errx.CheckVerifierErr(loadXdpObjects(&xdpObjs, nil), "Failed to load xdp objects")
		defer xdpObjs.Close()
		if xdpFirst == nil {
			xdpFirst = xdpObjs.XdpFn
		}

		info := errx.Must(xdpObjs.XdpFn.Info())
		if _, ok := info.BTFID(); !ok {
			log.Fatalf("xdp program %s does not have BTF ID", xdpObjs.XdpFn)
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
			errx.Check(frObjs.JmpTable.Put(uint32(0), xdpObjs.XdpFn), "Failed to put xdp program to jmp table")
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
