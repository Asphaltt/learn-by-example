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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang xdp ./xdp.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang freplace ./freplace.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang ff ./fentry_fexit.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach XDP program")
	flag.Parse()

	ifi, err := netlink.LinkByName(device)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", device, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var xdpObj xdpObjects
	if err := loadXdpObjects(&xdpObj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Printf("Failed to load bpf obj: %v", err)
		}
		return
	}
	defer xdpObj.Close()

	frSpec, err := loadFreplace()
	if err != nil {
		log.Printf("Failed to load freplace bpf spec: %v", err)
		return
	}

	frSpec.Programs["freplace_handler"].AttachTarget = xdpObj.XdpEntry

	var frObj freplaceObjects
	err = frSpec.LoadAndAssign(&frObj, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"events": xdpObj.Events,
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load freplace bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Printf("Failed to load freplace bpf obj: %v", err)
		}
		return
	}
	defer frObj.Close()

	ffSpec, err := loadFf()
	if err != nil {
		log.Printf("Failed to load fentry_fexit bpf spec: %v", err)
		return
	}

	funcName, err := bpf.GetProgEntryFuncName(frObj.FreplaceHandler)
	if err != nil {
		funcName = "freplace_handler"
		log.Printf("Failed to get function name: %v. Use %s instead", err, funcName)
	}

	fentryProg := ffSpec.Programs["fentry_freplace_handler"]
	fentryProg.AttachTarget = frObj.FreplaceHandler
	fentryProg.AttachTo = funcName
	fexitProg := ffSpec.Programs["fexit_freplace_handler"]
	fexitProg.AttachTarget = frObj.FreplaceHandler
	fexitProg.AttachTo = funcName

	var ffObj ffObjects
	err = ffSpec.LoadAndAssign(&ffObj, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"events": xdpObj.Events,
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load freplace bpf obj: %v\n%+v", err, ve)
		} else {
			log.Printf("Failed to load freplace bpf obj: %v", err)
		}
		return
	}
	defer ffObj.Close()

	if link, err := link.AttachTracing(link.TracingOptions{
		Program:    ffObj.FentryFreplaceHandler,
		AttachType: ebpf.AttachTraceFEntry,
	}); err != nil {
		log.Printf("Failed to attach fentry(freplace): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fentry(freplace)")
	}

	if link, err := link.AttachTracing(link.TracingOptions{
		Program:    ffObj.FexitFreplaceHandler,
		AttachType: ebpf.AttachTraceFExit,
	}); err != nil {
		log.Printf("Failed to attach fexit(freplace): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fexit(freplace)")
	}

	if fr, err := link.AttachFreplace(xdpObj.XdpEntry, "stub_handler", frObj.FreplaceHandler); err != nil {
		log.Printf("Failed to attach freplace on XDP: %v", err)
		return
	} else {
		defer fr.Close()
		log.Printf("Attached freplace on XDP")
	}

	if link, err := link.AttachXDP(link.XDPOptions{
		Interface: ifi.Attrs().Index,
		Program:   xdpObj.XdpEntry,
		Flags:     link.XDPGenericMode,
	}); err != nil {
		log.Printf("Failed to attach XDP: %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached XDP")
	}

	go handlePerfEvent(ctx, xdpObj.Events)

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
			log.Printf("Tracing packet: %s -> %s (fexit: %d)",
				netip.AddrFrom4(ev.Saddr),
				netip.AddrFrom4(ev.Daddr), ev.Verdict)
		case 3:
			log.Printf("Tracing packet: %s -> %s (freplace)",
				netip.AddrFrom4(ev.Saddr),
				netip.AddrFrom4(ev.Daddr))
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
