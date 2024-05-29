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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang tcpconn ./tcp-connecting.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang ff ./fentry_fexit.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var tcObj tcpconnObjects
	if err := loadTcpconnObjects(&tcObj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%+v", err, ve)
		} else {
			log.Fatalf("Failed to load bpf obj: %v", err)
		}
	}
	defer tcObj.Close()

	if err := tcObj.ProgArray.Put(uint32(0), tcObj.K_tailcall); err != nil {
		log.Fatalf("Failed to put k_tailcall: %v", err)
	}

	ffSpec, err := loadFf()
	if err != nil {
		log.Printf("Failed to load fentry_fexit bpf spec: %v", err)
		return
	}

	fentryProg := ffSpec.Programs["fentry_freplace_handler"]
	fentryProg.AttachTarget = tcObj.K_tcpConnect
	fentryProg.AttachTo = "stub_handler"
	fexitProg := ffSpec.Programs["fexit_freplace_handler"]
	fexitProg.AttachTarget = tcObj.K_tcpConnect
	fexitProg.AttachTo = "stub_handler"

	var ffObj ffObjects
	err = ffSpec.LoadAndAssign(&ffObj, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"socks":  tcObj.Socks,
			"events": tcObj.Events,
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load freplace bpf obj: %v\n%+v", err, ve)
		} else {
			log.Fatalf("Failed to load freplace bpf obj: %v", err)
		}
		return
	}
	defer ffObj.Close()

	if link, err := link.AttachTracing(link.TracingOptions{
		Program: ffObj.FentryFreplaceHandler,
	}); err != nil {
		log.Printf("Failed to attach fentry(freplace): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fentry(freplace)")
	}

	if link, err := link.AttachTracing(link.TracingOptions{
		Program: ffObj.FexitFreplaceHandler,
	}); err != nil {
		log.Printf("Failed to attach fexit(freplace): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fexit(freplace)")
	}

	if kprobe, err := link.Kprobe("tcp_connect", tcObj.K_tcpConnect, nil); err != nil {
		log.Printf("Failed to attach kprobe(tcp_connect): %v", err)
		return
	} else {
		defer kprobe.Close()
		log.Printf("Attached kprobe(tcp_connect)")
	}

	if kprobe, err := link.Kprobe("inet_csk_complete_hashdance", tcObj.K_icskCompleteHashdance, nil); err != nil {
		log.Printf("Failed to attach kprobe(inet_csk_complete_hashdance): %v", err)
		return
	} else {
		defer kprobe.Close()
		log.Printf("Attached kprobe(inet_csk_complete_hashdance)")
	}

	go handlePerfEvent(ctx, tcObj.Events)

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
		Sport, Dport uint16
		ProbeType    uint8
		Retval       uint8
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
			log.Printf("new tcp connection: %s:%d -> %s:%d (kprobe)",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport)

		case 1:
			log.Printf("new tcp connection: %s:%d -> %s:%d (fentry)",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport)

		case 2:
			log.Printf("new tcp connection: %s:%d -> %s:%d (fexit: %d)",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport, ev.Retval)

		case 3:
			log.Printf("new tcp connection: %s:%d -> %s:%d (freplace)",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
