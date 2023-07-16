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

	"internal/pkg/bpf"
	"internal/pkg/xdp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp ./xdp.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

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

	xdpDummy := spec.Programs["dummy"]
	dummyProg, err := ebpf.NewProgram(xdpDummy)
	if err != nil {
		log.Fatalf("Failed to create dummy program: %v", err)
	}
	defer dummyProg.Close()

	// get function name by dummy program
	funcName, err := bpf.GetFuncName(dummyProg)
	if err != nil {
		log.Printf("Failed to get function name: %v", err)
		return
	}

	log.Printf("XDP function name: %s", funcName)

	xdpFentry := spec.Programs["fentry_xdp"]
	xdpFentry.AttachTarget = dummyProg
	xdpFentry.AttachTo = funcName
	xdpFexit := spec.Programs["fexit_xdp"]
	xdpFexit.AttachTarget = dummyProg
	xdpFexit.AttachTo = funcName

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

	if link, err := link.AttachXDP(link.XDPOptions{
		Program:   dummyProg,
		Interface: ifi.Attrs().Index,
	}); err != nil {
		log.Printf("Failed to attach xdp to %s: %v", device, err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached xdp to %s", device)
	}

	if link, err := link.AttachTracing(link.TracingOptions{
		Program: obj.FentryXdp,
	}); err != nil {
		log.Printf("Failed to attach fentry(xdp): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fentry(xdp)")
	}

	// attach fexit(xdp) to the device
	if link, err := link.AttachTracing(link.TracingOptions{
		Program: obj.FexitXdp,
	}); err != nil {
		log.Printf("Failed to attach fexit(xdp): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fexit(xdp)")
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
		case 1:
			log.Printf("Tracing packet: %s -> %s (fentry)",
				netip.AddrFrom4(ev.Saddr),
				netip.AddrFrom4(ev.Daddr))
		case 2:
			log.Printf("Tracing packet: %s -> %s (fexit: %s)",
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
