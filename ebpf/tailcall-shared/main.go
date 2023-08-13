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
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpconn1 ./tcp-connecting.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpconn2 ./tcp-connecting.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp ./xdp.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

const (
	progArrayMapPinPath = "/sys/fs/bpf/tailcall-shared_progs"
	socksMapPinPath     = "/sys/fs/bpf/tailcall-shared_socks"
)

func main() {
	var runTcpConn1 bool
	var runTcpConn2 bool
	var runXdp bool
	flag.BoolVarP(&runTcpConn1, "tcpconn1", "1", false, "run tcpconn1")
	flag.BoolVarP(&runTcpConn2, "tcpconn2", "2", false, "run tcpconn2")
	flag.BoolVarP(&runXdp, "xdp", "x", false, "run xdp")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadTcpconn1()
	if err != nil {
		log.Printf("Failed to load bpf spec1: %v", err)
		return
	}

	loadOrCreateMap := func(name, pinPath string) (*ebpf.Map, error) {
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err == nil {
			return m, nil
		}

		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		m, err = ebpf.NewMap(spec.Maps[name])
		if err != nil {
			return nil, err
		}

		if err := m.Pin(pinPath); err != nil {
			_ = m.Close()
			return nil, err
		}

		return m, nil
	}

	progsMap, err := loadOrCreateMap("progs", progArrayMapPinPath)
	if err != nil {
		log.Printf("Failed to load or create progs map: %v", err)
		return
	}
	defer progsMap.Close()

	socksMap, err := loadOrCreateMap("socks", socksMapPinPath)
	if err != nil {
		log.Printf("Failed to load or create socks map: %v", err)
		return
	}
	defer socksMap.Close()

	var eventsMap *ebpf.Map

	if runTcpConn1 {
		var obj1 tcpconn1Objects
		if err := loadTcpconn1Objects(&obj1, &ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				"progs": progsMap,
				"socks": socksMap,
			},
		}); err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				log.Printf("Failed to load bpf obj1: %v\n%-20v", err, ve)
			} else {
				log.Printf("Failed to load bpf obj1: %v", err)
			}
			return
		}
		defer obj1.Close()

		// prepare programs for bpf_tail_call()
		prog := obj1.tcpconn1Programs.HandleNewConnection1
		key := uint32(0)
		if err := obj1.tcpconn1Maps.Progs.Update(key, prog, ebpf.UpdateAny); err != nil {
			log.Printf("Failed to prepare tailcall(handle_new_connection1): %v", err)
			return
		} else {
			log.Printf("Prepared tailcall(handle_new_connection1)")
		}

		if kp, err := link.Kprobe("tcp_connect", obj1.K_tcpConnect, nil); err != nil {
			log.Printf("Failed to attach kprobe(tcp_connect): %v", err)
			return
		} else {
			defer kp.Close()
			log.Printf("Attached kprobe(tcp_connect)")
		}

		eventsMap = obj1.Events
	}

	if runTcpConn2 {
		var obj2 tcpconn2Objects
		if err := loadTcpconn2Objects(&obj2, &ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				"progs": progsMap,
				"socks": socksMap,
			},
		}); err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				log.Printf("Failed to load bpf obj2: %v\n%-20v", err, ve)
			} else {
				log.Printf("Failed to load bpf obj2: %v", err)
			}
			return
		}

		// prepare programs for bpf_tail_call()
		prog := obj2.tcpconn2Programs.HandleNewConnection2
		key := uint32(0)
		if err := obj2.tcpconn2Maps.Progs.Update(key, prog, ebpf.UpdateAny); err != nil {
			log.Printf("Failed to prepare tailcall(handle_new_connection2): %v", err)
			return
		} else {
			log.Printf("Prepared tailcall(handle_new_connection2)")
		}

		if kp, err := link.Kprobe("inet_csk_complete_hashdance", obj2.K_icskCompleteHashdance, nil); err != nil {
			log.Printf("Failed to attach kprobe(inet_csk_complete_hashdance): %v", err)
			return
		} else {
			defer kp.Close()
			log.Printf("Attached kprobe(inet_csk_complete_hashdance)")
		}

		eventsMap = obj2.Events
	}

	if runXdp {
		var xdpObj xdpObjects
		var xdpOk bool
		if err := loadXdpObjects(&xdpObj, &ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				"progs": progsMap,
			},
		}); err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				log.Printf("Failed to load bpf xdp: %v\n%-20v", err, ve)
			} else {
				log.Printf("Failed to load bpf xdp: %v", err)
			}
			return
		} else {
			xdpOk = true
		}
		defer func() {
			if xdpOk {
				xdpObj.Close()
			}
		}()

		if xdpOk {
			if xdp, err := link.AttachXDP(link.XDPOptions{
				Program:   xdpObj.XdpEntry,
				Interface: 1,
				Flags:     link.XDPGenericMode,
			}); err != nil {
				log.Printf("Failed to attach xdp: %v", err)
			} else {
				defer xdp.Close()
				log.Printf("Attached xdp")
			}
		}
	}

	if eventsMap == nil {
		log.Printf("No program to run")
		return
	}

	go handlePerfEvent(ctx, eventsMap)

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
			log.Printf("new tcp connection: %s:%d -> %s:%d (handle_new_connection1)",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport)
		case 2:
			log.Printf("new tcp connection: %s:%d -> %s:%d (handle_new_connection2)",
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
