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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpconn ./tcp-connecting.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fentry ./fentry.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadFentry()
	if err != nil {
		log.Printf("Failed to load bpf obj: %v", err)
		return
	}

	progArray, err := ebpf.NewMap(spec.Maps["prog_array"])
	if err != nil {
		log.Printf("Failed to create prog_array: %v", err)
		return
	}

	var obj tcpconnObjects
	if err := loadTcpconnObjects(&obj, nil); err != nil {
		log.Fatalf("Failed to load bpf obj: %v", err)
	}
	defer obj.Close()

	if err := progArray.Put(uint32(0), obj.K_tcpConnect); err != nil {
		log.Printf("Failed to put program into array: %v", err)
		return
	}

	funcName := "handle_new_connection"

	bpf2bpfFentry := spec.Programs["fentry_bpf2bpf"]
	bpf2bpfFentry.AttachTarget = obj.tcpconnPrograms.K_tcpConnect
	bpf2bpfFentry.AttachTo = funcName

	var fObj fentryObjects
	if err := spec.LoadAndAssign(&fObj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:    ebpf.LogLevelInstruction | ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogSize:     10 * ebpf.DefaultVerifierLogSize,
			LogDisabled: false,
		},
		MapReplacements: map[string]*ebpf.Map{
			"events":     obj.Events,
			"prog_array": progArray,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load fentry bpf obj: %v\n%+v", err, ve)
		} else {
			log.Printf("Failed to load fentry bpf obj: %v", err)
		}
		return
	}
	defer fObj.Close()

	if link, err := link.AttachTracing(link.TracingOptions{
		Program: fObj.FentryBpf2bpf,
	}); err != nil {
		log.Printf("Failed to attach fentry(bpf2bpf): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fentry(bpf2bpf)")
	}

	if kp, err := link.Kprobe("tcp_connect", obj.K_tcpConnect, nil); err != nil {
		log.Printf("Failed to attach kprobe(tcp_connect): %v", err)
		return
	} else {
		defer kp.Close()
		log.Printf("Attached kprobe(tcp_connect)")
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

	cnt := 0

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
		case 0:
			log.Printf("new tcp connection: %s:%d -> %s:%d (kprobe)",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport)
		case 1:
			log.Printf("new tcp connection: %s:%d -> %s:%d (fentry %d times)",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport, cnt)
			cnt++
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
