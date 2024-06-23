// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/tklauser/ps"
	"golang.org/x/sync/errgroup"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang rpsxps ./rpsxps.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	var obj rpsxpsObjects
	if err := loadRpsxpsObjects(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%+v", err, ve)
		}
		log.Fatalf("Failed to load bpf obj: %v", err)
	}
	defer obj.Close()

	if l, err := link.AttachTracing(link.TracingOptions{
		Program: obj.FexitStoreRpsMap,
	}); err != nil {
		log.Fatalf("Failed to attach fexit/store_rps_map: %v", err)
	} else {
		log.Printf("Attached fexit/store_rps_map")
		defer l.Close()
	}

	if l, err := link.AttachTracing(link.TracingOptions{
		Program: obj.FexitXpsCpusStore,
	}); err != nil {
		log.Fatalf("Failed to attach fexit/xps_cpus_store: %v", err)
	} else {
		log.Printf("Attached fexit/xps_cpus_store")
		defer l.Close()
	}

	events := obj.Events
	reader, err := perf.NewReader(events, os.Getpagesize()*2)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		var event struct {
			Cpus      [32]byte
			CpusLen   uint32
			Ifindex   uint32
			Queue     uint64
			QueueBase uint64
			QueueSize uint32
			Pid       uint32
			IsRps     uint8
			Pad       [3]uint8
		}

		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return nil
				}

				return fmt.Errorf("failed to read record: %w", err)
			}

			if record.LostSamples != 0 {
				log.Printf("Lost %d events", record.LostSamples)
			}

			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				return fmt.Errorf("failed to decode event: %w", err)
			}

			ifindex := event.Ifindex
			ifi, err := net.InterfaceByIndex(int(ifindex))
			if err != nil {
				return fmt.Errorf("failed to get interface by index(%d): %w", ifindex, err)
			}

			proc, err := ps.FindProcess(int(event.Pid))
			if err != nil {
				return fmt.Errorf("failed to find process(%d): %w", event.Pid, err)
			}

			c := event.Cpus[:]
			if event.CpusLen < 32 {
				c = c[:event.CpusLen]
			}

			x := "XPS:"
			if event.IsRps != 0 {
				x = "RPS:"
			}

			ifname := ifi.Name
			p := proc.ExecutablePath()
			q := (event.Queue - event.QueueBase) / uint64(event.QueueSize)

			log.Printf("%s %s(%d) Queue: %d Process: %s(%d) Cpus: %#x",
				x, ifname, ifindex, q, p, event.Pid, c)
		}
	})

	if err := errg.Wait(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
