// SPDX-License-Identifier: MIT
// Copyright 2024 Leon Hwang.

package main

import (
	"context"
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcx ./tcx.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach tc-bpf program")
	flag.Parse()

	ifi, err := netlink.LinkByName(device)
	if err != nil {
		log.Fatalf("Failed to get link by name: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var obj tcxObjects
	if err := loadTcxObjects(&obj, nil); err != nil {
		log.Fatalf("Failed to load tcx objects: %v", err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifi.Attrs().Index,
		Program:   obj.Dummy,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("Failed to attach tcx program: %v", err)
	}
	defer l.Close()

	log.Println("Attached tcx program to", device, "interface")

	<-ctx.Done()
}
