// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"internal/pkg/bpf"
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpconn ./tcp-connecting.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fentryFexit ./fentry_fexit.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var withoutTracing bool
	flag.BoolVar(&withoutTracing, "T", false, "without tracing")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var obj tcpconnObjects
	if err := loadTcpconnObjects(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Printf("Failed to load bpf obj: %v", err)
		}
		return
	}
	defer obj.Close()

	spec, err := loadFentryFexit()
	if err != nil {
		log.Printf("Failed to load bpf obj: %v", err)
		return
	}

	funcName, err := bpf.GetProgEntryFuncName(obj.K_tcpConnect)
	if err != nil {
		funcName = "k_tcp_connect"
		log.Printf("Failed to get function name: %v. Use %s instead", err, funcName)
	}

	kprobeFentry := spec.Programs["fentry_kprobe"]
	kprobeFentry.AttachTarget = obj.tcpconnPrograms.K_tcpConnect
	kprobeFentry.AttachTo = funcName
	kprobeFexit := spec.Programs["fexit_kprobe"]
	kprobeFexit.AttachTarget = obj.tcpconnPrograms.K_tcpConnect
	kprobeFexit.AttachTo = funcName

	var ffObj fentryFexitObjects
	if err := spec.LoadAndAssign(&ffObj, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"events": obj.Events,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Printf("Failed to load bpf obj: %v", err)
		}
		return
	}
	defer ffObj.Close()

	if !withoutTracing {
		if link, err := link.AttachTracing(link.TracingOptions{
			Program: ffObj.FentryKprobe,
		}); err != nil {
			log.Printf("Failed to attach fentry(tcp_connect): %v", err)
			return
		} else {
			defer link.Close()
			log.Printf("Attached fentry(tcp_connect)")
		}

		if link, err := link.AttachTracing(link.TracingOptions{
			Program: ffObj.FexitKprobe,
		}); err != nil {
			log.Printf("Failed to attach fexit(tcp_connect): %v", err)
			return
		} else {
			defer link.Close()
			log.Printf("Attached fexit(tcp_connect)")
		}
	}

	// prepare programs for bpf_tail_call()
	prog := obj.tcpconnPrograms.HandleNewConnection
	key := uint32(0)
	if err := obj.tcpconnMaps.Progs.Update(key, prog, ebpf.UpdateAny); err != nil {
		return
	}

	if kp, err := link.Kprobe("tcp_connect", obj.K_tcpConnect, nil); err != nil {
		log.Printf("Failed to attach kprobe(tcp_connect): %v", err)
		return
	} else {
		defer kp.Close()
		log.Printf("Attached kprobe(tcp_connect)")
	}

	if kp, err := link.Kprobe("inet_csk_complete_hashdance", obj.K_icskCompleteHashdance, nil); err != nil {
		log.Printf("Failed to attach kprobe(inet_csk_complete_hashdance): %v", err)
		return
	} else {
		defer kp.Close()
		log.Printf("Attached kprobe(inet_csk_complete_hashdance)")
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
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
