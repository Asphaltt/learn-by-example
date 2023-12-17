// SPDX-License-Identifier: MIT
// Copyright 2023 Leon Hwang.

package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/spf13/cobra"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang traceroute ./traceroute.c -- -D__TARGET_ARCH_x86 -I../headers -Wall -mcpu=v3

var flags struct {
	device string
	addr   string
}

var rootCmd = cobra.Command{
	Use: "xdp-traceroute",
}

func main() {
	_ = rootCmd.Execute()
}

func init() {
	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		runXDPTraceroute()
	}

	flag := rootCmd.PersistentFlags()
	flag.StringVar(&flags.device, "dev", "", "device to run XDP")
	flag.StringVar(&flags.addr, "addr", "", "address to traceroute, empty to retrieve from --dev")
}

func runXDPTraceroute() {
	ifi, err := net.InterfaceByName(flags.device)
	if err != nil {
		log.Fatalf("Failed to fetch device info of %s: %v", flags.device, err)
	}

	var addr netip.Addr
	if flags.addr != "" {
		addr, err = netip.ParseAddr(flags.addr)
		if err != nil {
			log.Fatalf("Failed to parse address %s: %v", flags.addr, err)
		}
	} else {
		addrs, err := ifi.Addrs()
		if err != nil {
			log.Fatalf("Failed to fetch address of %s: %v", flags.device, err)
		}

		if len(addrs) == 0 {
			log.Fatalf("No address found for %s", flags.device)
		}

		var ok bool
		addr, ok = netip.AddrFromSlice(addrs[0].(*net.IPNet).IP)
		if !ok {
			log.Fatalf("Failed to convert address %s to netip.Addr", addrs[0].(*net.IPNet).IP)
		}
	}

	spec, err := loadTraceroute()
	if err != nil {
		log.Fatalf("Failed to load traceroute bpf spec: %v", err)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"MY_ADDR": addr.As4(),
	}); err != nil {
		log.Fatalf("Failed to rewrite constants: %v", err)
	}

	var obj tracerouteObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load traceroute bpf obj: %v\n%+v", err, ve)
		}
		log.Fatalf("Failed to load traceroute bpf obj: %v", err)
	}
	defer obj.Close()

	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.Traceroute,
		Interface: ifi.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach traceroute to %s: %v", flags.device, err)
	}
	defer xdp.Close()

	log.Printf("traceroute is running on %s\n", flags.device)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	<-ctx.Done()
}
