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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpconn ./tcp-connecting.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang freplace ./freplace.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var waitExit bool
	flag.BoolVarP(&waitExit, "wait", "w", false, "wait for exit")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var tcObj tcpconnObjects
	if err := loadTcpconnObjects(&tcObj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Fatalf("Failed to load bpf obj: %v", err)
		}
	}
	defer tcObj.Close()

	frSpec, err := loadFreplace()
	if err != nil {
		log.Printf("Failed to load freplace bpf spec: %v", err)
		return
	}

	frSpec.Programs["freplace_handler"].AttachTarget = tcObj.K_tcpConnect

	var frObj freplaceObjects
	err = frSpec.LoadAndAssign(&frObj, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"socks":  tcObj.Socks,
			"events": tcObj.Events,
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load freplace bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Fatalf("Failed to load freplace bpf obj: %v", err)
		}
		return
	}
	defer frObj.Close()

	if waitExit {
		log.Println("Waiting for exit...")
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		<-ctx.Done()
		return
	}

	if err := frObj.Progs.Put(uint32(0), frObj.K_tailcall); err != nil {
		log.Printf("Failed to put tailcall: %v", err)
		return
	} else {
		log.Printf("Put tailcall")
		defer frObj.Progs.Delete(uint32(0))
	}

	fr, err := link.AttachFreplace(tcObj.K_tcpConnect, "stub_handler", frObj.FreplaceHandler)
	if err != nil {
		log.Printf("Failed to freplace: %v", err)
		return
	}
	defer fr.Close()

	fr, err = link.AttachFreplace(tcObj.K_icskCompleteHashdance, "stub_handler", frObj.FreplaceHandler)
	if err != nil {
		log.Printf("Failed to freplace: %v", err)
		return
	}
	defer fr.Close()

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

	freplaceCnt := 0

	var ev struct {
		Saddr, Daddr [4]byte
		Sport, Dport uint16
		Type         uint8
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

		switch ev.Type {
		default:
			log.Printf("tcp connection: %s:%d -> %s:%d",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport)

		case 3:
			log.Printf("tcp connection: %s:%d -> %s:%d (freplace: %d)",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport,
				freplaceCnt)
			freplaceCnt++
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
