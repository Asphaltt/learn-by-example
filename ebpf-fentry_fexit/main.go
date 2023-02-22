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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpconn ./tcp-connecting.c -- -D__TARGET_ARCH_x86 -I../ebpf-headers -Wall

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadTcpconn()
	if err != nil {
		log.Fatalf("Failed to load tcpconn bpf spec: %v", err)
		return
	}

	var obj tcpconnObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Fatalf("Failed to load bpf obj: %v", err)
		}
	}
	defer obj.Close()

	if link, err := link.AttachTracing(link.TracingOptions{
		Program: obj.TcpConnect,
	}); err != nil {
		log.Printf("Failed to attach fentry(tcp_connect): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fentry(tcp_connect)")
	}

	if link, err := link.AttachTracing(link.TracingOptions{
		Program: obj.InetCskCompleteHashdance,
	}); err != nil {
		log.Printf("Failed to attach fexit(inet_csk_complete_hashdance): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fexit(inet_csk_complete_hashdance)")
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

		log.Printf("new tcp connection: %s:%d -> %s:%d",
			netip.AddrFrom4(ev.Saddr), ev.Sport,
			netip.AddrFrom4(ev.Daddr), ev.Dport)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
