// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"internal/assert"
	"internal/endx"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcp ./tcp.c -- -g -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var dport uint16
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach XDP program")
	flag.Uint16VarP(&dport, "dport", "D", 65535, "destination port to reset tcp connection")
	flag.Parse()

	if dport == 0 {
		log.Fatalf("dport should be greater than 0")
	}

	ifi, err := netlink.LinkByName(device)
	assert.NoErr(err, "Failed to get link by name: %v", device)

	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadTcp()
	assert.NoErr(err, "Failed to load xdp bpf spec: %v")

	err = spec.Variables["DPORT"].Set(endx.Htons(dport))
	assert.NoErr(err, "Failed to set DPORT: %v", dport)

	coll, err := ebpf.NewCollection(spec)
	assert.NoErr(err, "Failed to create ebpf collection: %v", err)
	defer coll.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["xdp_fn"],
		Interface: ifi.Attrs().Index,
	})
	assert.NoErr(err, "Failed to attach xdp(%s): %v", device)
	defer l.Close()

	log.Printf("Attached xdp to %s", device)

	<-ctx.Done()
}
