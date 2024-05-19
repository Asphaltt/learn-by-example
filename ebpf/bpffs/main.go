// Copyright (c) 2024 Leon Hwang
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/iovisor/gobpf/pkg/bpffs"
	"github.com/spf13/cobra"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang traceroute ../xdp-traceroute/traceroute.c -- -D__TARGET_ARCH_x86 -I../headers -Wall -mcpu=v3

const (
	bpffsPath     = "./test-bpffs-dir"
	tracerouteDir = bpffsPath + "/traceroute"
	bakDir        = bpffsPath + "/bak"
)

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

	if err := os.Mkdir(bpffsPath, 0o755); err != nil {
		log.Fatalf("Failed to create bpffs dir: %v", err)
	}
	defer os.RemoveAll(bpffsPath)

	if err := bpffs.MountAt(bpffsPath); err != nil {
		log.Fatalf("Failed to mount bpffs: %v", err)
	}
	defer syscall.Unmount(bpffsPath, 0)
	defer os.RemoveAll(bpffsPath)

	if err := os.MkdirAll(tracerouteDir, 0o755); err != nil {
		log.Fatalf("Failed to create bpffs dir: %v", err)
	}
	defer os.RemoveAll(tracerouteDir)

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

	progPinPath := filepath.Join(tracerouteDir, "traceroute")
	if err := obj.Traceroute.Pin(progPinPath); err != nil {
		log.Fatalf("Failed to pin traceroute: %v", err)
	}
	defer obj.Traceroute.Unpin()

	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.Traceroute,
		Interface: ifi.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach traceroute to %s: %v", flags.device, err)
	}
	defer xdp.Close()

	xdpPinPath := filepath.Join(tracerouteDir, "xdp")
	if err := xdp.Pin(xdpPinPath); err != nil {
		log.Fatalf("Failed to pin xdp: %v", err)
	}
	defer xdp.Unpin()

	log.Printf("traceroute is running on %s\n", flags.device)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	<-ctx.Done()
}
