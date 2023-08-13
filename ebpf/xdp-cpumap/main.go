// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"internal/pkg/xdp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp ./xdp.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

type CPUVal struct {
	Qsize uint32
	FD    uint32 // it's int in kernel
}

func main() {
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach XDP program")
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

	spec, err := loadXdp()
	if err != nil {
		log.Fatalf("Failed to load tcpconn bpf spec: %v", err)
		return
	}

	// Note: It's necessary to set AttachType as AttachXDPCPUMap before
	// LoadAndAssign.
	// It's because go-ebpf does not recognize AttachType of AttachXDPCPUMap.
	spec.Programs["xdp_cpumap"].AttachType = ebpf.AttachXDPCPUMap

	var obj xdpObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Fatalf("Failed to load bpf obj: %v", err)
		}
	}
	defer obj.Close()

	var cpuval CPUVal
	cpuval.Qsize = 1000
	cpuval.FD = uint32(obj.XdpCpumap.FD())

	tgtCPU := uint32(2)
	if err := obj.RedirectMap.Put(tgtCPU, &cpuval); err != nil {
		log.Printf("Failed to put redirect map: %+v", err)
		return
	} else {
		log.Printf("Put redirect map: %v", cpuval)
	}

	if link, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.XdpNative,
		Interface: ifi.Attrs().Index,
		Flags:     link.XDPGenericMode, // generic mode for demo
	}); err != nil {
		log.Printf("Failed to attach xdp to %s: %v", device, err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached xdp to %s", device)
	}

	go handlePerfEvent(ctx, obj.Events)

	<-ctx.Done()
}

func handlePerfEvent(ctx context.Context, events *ebpf.Map) {
	eventReader, err := perf.NewReader(events, 4096)
	if err != nil {
		log.Printf("Failed to create perf-event reader: %v", err)
		return
	}

	log.Printf("Listening events...")

	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()

	var ev struct {
		Saddr, Daddr [4]byte
		ProbeType    uint8
		Verdict      xdp.Action
		Pad          uint16
	}
	for {
		event, err := eventReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			log.Printf("Reading perf-event: %v", err)
		}

		if event.LostSamples != 0 {
			log.Printf("Lost %d events", event.LostSamples)
		}

		binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev)

		switch ev.ProbeType {
		default:
			log.Printf("Tracing packet: %s -> %s on CPU:%d (native)",
				netip.AddrFrom4(ev.Saddr),
				netip.AddrFrom4(ev.Daddr), ev.Verdict)
		case 1:
			log.Printf("Tracing packet: %s -> %s on CPU:%d (cpumap)",
				netip.AddrFrom4(ev.Saddr),
				netip.AddrFrom4(ev.Daddr), ev.Verdict)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
