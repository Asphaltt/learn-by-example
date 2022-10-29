package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/iovisor/gobpf/pkg/bpffs"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpconn ./tcp-connecting.c -- -D__TARGET_ARCH_x86 -I../ebpf-headers -Wall

func main() {
	var toGenBssStruct, noPin bool
	var daddr string
	var dport uint
	flag.BoolVar(&toGenBssStruct, "gen", false, "Generate Go struct for .bss map value")
	flag.BoolVar(&noPin, "no-pin", false, "Do not pin .bss map")
	flag.StringVar(&daddr, "daddr", "", "Dest addr is required")
	flag.UintVar(&dport, "dport", 0, "Dest port is required")
	flag.Parse()

	if toGenBssStruct {
		genBssStruct()
		return
	}

	dip, err := netip.ParseAddr(daddr)
	if err != nil {
		log.Fatalf("-daddr is not a valid IP address")
	}
	if !dip.Is4() {
		log.Fatalf("-daddr is not a valid IPv4 address")
	}

	if dport == 0 || dport >= 1<<16 {
		log.Fatal("A valid dest port is required")
	}

	if err := bpffs.Mount(); err != nil {
		log.Fatalf("Failed to mount bpffs: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bpfSpec, err := loadTcpconn()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	var bssVal bssValue
	bssVal.Daddr = dip.As4()
	bssVal.Dport = uint16(dport)

	var obj tcpconnObjects
	if !noPin {
		bssMap := loadBssMap(bpfSpec.Maps[".bss"])
		replacedMaps := make(map[string]*ebpf.Map)
		replacedMaps[".bss"] = bssMap

		if err := bssMap.Put(uint32(0), bssVal); err != nil {
			log.Fatalf("Failed to update .bss map: %v", err)
		}

		if err := bpfSpec.LoadAndAssign(&obj, &ebpf.CollectionOptions{
			MapReplacements: replacedMaps,
		}); err != nil {
			log.Fatalf("Failed to load bpf obj: %v", err)
		}
		defer obj.Close()

	} else {
		bpfSpec.Maps[".bss"].Contents = []ebpf.MapKV{
			{Key: uint32(0), Value: bssVal},
		}

		if err := bpfSpec.LoadAndAssign(&obj, nil); err != nil {
			log.Fatalf("Failed to load bpf obj: %v", err)
		}

		defer obj.Close()
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
