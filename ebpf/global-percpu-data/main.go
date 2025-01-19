package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"internal/assert"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sync/errgroup"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang data ./data.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove memlock limit: %v")

	numCPU, err := ebpf.PossibleCPU()
	assert.NoErr(err, "Failed to get number of CPUs: %v")

	spec, err := loadData()
	assert.NoErr(err, "Failed to load data: %v")

	spec.Maps[".data.percpu"].Type = ebpf.PerCPUArray
	spec.Maps[".data.percpu"].Contents = []ebpf.MapKV{
		{Key: uint32(0), Value: make([]uint32, numCPU)},
	}
	perCPU, err := ebpf.NewMap(spec.Maps[".data.percpu"])
	assert.NoErr(err, "Failed to create percpu map: %v")
	defer perCPU.Close()

	spec.Maps["ringbuf"].MaxEntries = 4096
	events, err := ebpf.NewMap(spec.Maps["ringbuf"])
	assert.NoErr(err, "Failed to create ringbuf map: %v")
	defer events.Close()

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			".data.percpu": perCPU,
			"ringbuf":      events,
		},
	})
	assert.NoVerifierErr(err, "Failed to create BPF collection: %v")
	defer coll.Close()

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    coll.Programs["fentry_nanosleep"],
		AttachType: ebpf.AttachTraceFEntry,
	})
	assert.NoErr(err, "Failed to attach fentry(sys_nanosleep): %v")
	defer l.Close()

	reader, err := ringbuf.NewReader(events)
	assert.NoErr(err, "Failed to create ringbuf reader: %v")
	defer reader.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		defer stop()

		type Event struct {
			Data uint32
			CPU  uint32
		}

		// Trigger an event

		nanosleep()

		var rec ringbuf.Record
		rec.RawSample = make([]byte, 8)

		for {
			if err := reader.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return nil
				}
				return err
			}

			event := Event{
				Data: binary.NativeEndian.Uint32(rec.RawSample[:4]),
				CPU:  binary.NativeEndian.Uint32(rec.RawSample[4:]),
			}

			fmt.Println("Event:", event.Data, "CPU:", event.CPU)

			// return nil
		}
	})

	<-ctx.Done()

	vals := make([]uint32, numCPU)
	err = perCPU.Lookup(uint32(0), vals)
	assert.NoErr(err, "Failed to read percpu map: %v")

	fmt.Printf("Per-CPU data: %v\n", vals)
}
