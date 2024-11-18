// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	"internal/pkg/bpf"
	"internal/pkg/errx"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang lbr ./lbr.c -- -g -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var progID uint
	flag.UintVarP(&progID, "prog-id", "p", 0, "Program ID")
	flag.Parse()

	errx.Check(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock")

	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	errx.Check(err, "Failed to load program from ID: %d", progID)
	defer prog.Close()

	progEntry, err := bpf.GetProgEntryFuncName(prog)
	errx.Check(err, "Failed to get program entry function name")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadLbr()
	errx.Check(err, "Failed to load xdp bpf spec")

	const progName = "fexit_fn"

	spec.Programs[progName].AttachTarget = prog
	spec.Programs[progName].AttachTo = progEntry

	var objs lbrObjects
	err = spec.LoadAndAssign(&objs, nil)
	errx.CheckVerifierErr(err, "Failed to load and assign lbr objects")
	defer objs.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	errx.Check(err, "Failed to create ringbuf reader")
	defer reader.Close()

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		l, err := link.AttachTracing(link.TracingOptions{
			Program:    objs.FexitFn,
			AttachType: ebpf.AttachTraceFExit,
		})
		if err != nil {
			return fmt.Errorf("failed to attach tracing: %w", err)
		}
		defer l.Close()

		<-ctx.Done()

		return nil
	})

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		type LbrEntry struct {
			From  uint64
			To    uint64
			Flags LbrEntryFlags
		}
		type Event struct {
			Entries [32]LbrEntry
			NrBytes int64
			Retval  int64
		}

		var sb strings.Builder

		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return nil
				}

				return fmt.Errorf("failed to read ringbuf: %w", err)
			}

			event := (*Event)(unsafe.Pointer(&record.RawSample[0]))

			sb.Reset()
			var errno string
			if event.NrBytes < 0 {
				errno = fmt.Sprintf("(ERR: %s)", unix.Errno(-event.NrBytes).Error())
			}
			fmt.Fprintf(&sb, "Recv a record for %s: retval=%d nr_bytes=%d%s\n", progEntry, event.Retval, event.NrBytes, errno)
			if event.NrBytes > 0 {
				nrEntries := event.NrBytes / int64(8*3)
				i := 0
				for ; i < int(nrEntries); i++ {
					entry := event.Entries[i]
					if entry == (LbrEntry{}) {
						break
					}
					fmt.Fprintf(&sb, "\t%#x -> %#x, flags=%s\n", entry.From, entry.To, entry.Flags)
				}
				if i != 0 {
					fmt.Fprintf(&sb, "\t%d entries\n", i)
				}
			}
			fmt.Println(sb.String())
		}
	})

	log.Printf("Attached fexit program %s to %s", progName, progEntry)

	<-ctx.Done()
}

type LbrEntryFlags uint64

func (f LbrEntryFlags) String() string {
	var s []string

	if f&(1<<0) != 0 {
		s = append(s, "MISPREDICTED")
	}

	if f&(1<<1) != 0 {
		s = append(s, "PREDICTED")
	}

	if f&(1<<2) != 0 {
		s = append(s, "IN_TX")
	}

	if f&(1<<3) != 0 {
		s = append(s, "ABORT")
	}

	if cycles := (f >> 4) & ((1 << 16) - 1); cycles != 0 {
		s = append(s, fmt.Sprintf("CYCLES=%d", cycles))
	}

	if typ := (f >> 20) & ((1 << 4) - 1); typ != 0 {
		s = append(s, fmt.Sprintf("TYPE=%d", typ))
	}

	if spec := (f >> 24) & ((1 << 2) - 1); spec != 0 {
		s = append(s, fmt.Sprintf("SPEC=%d", spec))
	}

	if typ := (f >> 26) & ((1 << 4) - 1); typ != 0 {
		s = append(s, fmt.Sprintf("TYPE=%d", typ))
	}

	if priv := (f >> 30) & ((1 << 3) - 1); priv != 0 {
		s = append(s, fmt.Sprintf("PRIV=%d", priv))
	}

	if res := (f >> 33) & ((1 << 31) - 1); res != 0 {
		s = append(s, fmt.Sprintf("RESERVED=%d", res))
	}

	return strings.Join(s, "|")
}
