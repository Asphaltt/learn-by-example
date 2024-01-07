// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tailcall ./tailcall.c -- -D__TARGET_ARCH_x86 -I../headers -Wall -g

var flags struct {
	device string
}

func init() {
	flag.StringVar(&flags.device, "dev", "", "device to run XDP")
	flag.Parse()

	if flags.device == "" {
		log.Fatal("Please specify device to run XDP")
	}
}

func main() {
	ifi, err := net.InterfaceByName(flags.device)
	if err != nil {
		log.Fatalf("Failed to fetch device info of %s: %v", flags.device, err)
	}

	var obj tailcallObjects
	if err := loadTailcallObjects(&obj, nil); err != nil {
		log.Fatalf("Failed to load tailcall-in-bpf2bpf bpf obj: %v", err)
	}
	defer obj.Close()

	if err := obj.ProgArray.Put(uint32(0), obj.XdpProg1); err != nil {
		log.Fatalf("Failed to save xdp_prog1 to prog_array: %v", err)
	}

	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.XdpEntry,
		Interface: ifi.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach tailcall-in-bpf2bpf to %s: %v", flags.device, err)
	}
	defer xdp.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("tailcall-in-bpf2bpf is running on %s\n", flags.device)

	<-ctx.Done()
}
