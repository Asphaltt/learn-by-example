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
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp ./xdp.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach XDP program")
	flag.Parse()

	ifi := errx.Must(netlink.LinkByName(device))

	errx.Check(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var obj xdpObjects
	errx.CheckVerifierErr(loadXdpObjects(&obj, nil), "Failed to load xdp objects")
	defer obj.Close()

	xdp := errx.Must(link.AttachXDP(link.XDPOptions{
		Program:   obj.Crc,
		Interface: ifi.Attrs().Index,
	}))
	defer xdp.Close()

	log.Printf("Attached xdp to %s", device)

	<-ctx.Done()
}
