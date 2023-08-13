// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpconn ./tcp-connecting.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fentry ./fentry.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fexit ./fexit.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

const nTailcalls = 36

func main() {
	var runLess bool
	var runFentry bool
	var runFexit bool
	flag.BoolVar(&runLess, "run-less", false, "run less tailcalls")
	flag.BoolVar(&runFentry, "run-fentry", false, "don't run fentry")
	flag.BoolVar(&runFexit, "run-fexit", false, "don't run fexit")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	spec, err := loadTcpconn()
	if err != nil {
		log.Fatalf("Failed to load program spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load program collection: %v\n%-20v", err, ve)
			return
		}

		log.Printf("Failed to create program collection: %v", err)
		return
	}
	defer coll.Close()

	n := nTailcalls
	if runLess {
		n--
	}

	progsMap := coll.Maps["progs"]
	for i := 0; i < n; i++ {
		tailcall := fmt.Sprintf("k_tailcall%d", i)
		if err := progsMap.Put(uint32(i), coll.Programs[tailcall]); err != nil {
			log.Printf("Failed to put program into map: %v", err)
			return
		} else {
			log.Printf("Put prog(%s) into map", tailcall)
		}
	}

	if kp, err := link.Kprobe("tcp_connect", coll.Programs["k_tcp_connect"], nil); err != nil {
		log.Printf("Failed to create kprobe: %v", err)
		return
	} else {
		log.Printf("Attached kprobe(k_tcp_connect)")
		defer kp.Close()
	}

	if runFentry {
		spec, err = loadFentry()
		if err != nil {
			log.Printf("Failed to load trace program spec: %v", err)
			return
		}

		tailcall := fmt.Sprintf("__tailcall%d", 0)
		spec.Programs["fentry"+tailcall].AttachTarget = coll.Programs["k_tcp_connect"]
		spec.Programs["fentry"+tailcall].AttachTo = tailcall

		for i := 1; i < nTailcalls; i++ {
			tailcall := fmt.Sprintf("__tailcall%d", i)
			spec.Programs["fentry"+tailcall].AttachTarget = coll.Programs[fmt.Sprintf("k_tailcall%d", i-1)]
			spec.Programs["fentry"+tailcall].AttachTo = tailcall
		}

		fentryColl, err := ebpf.NewCollection(spec)
		if err != nil {
			log.Printf("Failed to load fentry collection: %v", err)
			return
		}
		defer fentryColl.Close()

		for i := 0; i < nTailcalls; i++ {
			tailcall := fmt.Sprintf("__tailcall%d", i)
			prog := fentryColl.Programs["fentry"+tailcall]

			if link, err := link.AttachTracing(link.TracingOptions{
				Program: prog,
			}); err != nil {
				log.Printf("Failed to attach fentry(%s): %v", tailcall, err)
				return
			} else {
				log.Printf("Attached fentry(%s)", tailcall)
				defer link.Close()
			}
		}
	}

	if runFexit {
		spec, err = loadFexit()
		if err != nil {
			log.Printf("Failed to load trace program spec: %v", err)
			return
		}

		tailcall := fmt.Sprintf("__tailcall%d", 0)
		spec.Programs["fexit"+tailcall].AttachTarget = coll.Programs["k_tcp_connect"]
		spec.Programs["fexit"+tailcall].AttachTo = tailcall

		for i := 1; i < nTailcalls; i++ {
			tailcall := fmt.Sprintf("__tailcall%d", i)
			spec.Programs["fexit"+tailcall].AttachTarget = coll.Programs[fmt.Sprintf("k_tailcall%d", i-1)]
			spec.Programs["fexit"+tailcall].AttachTo = tailcall
		}

		fexitColl, err := ebpf.NewCollection(spec)
		if err != nil {
			log.Printf("Failed to load fexit collection: %v", err)
			return
		}
		defer fexitColl.Close()

		for i := 0; i < nTailcalls; i++ {
			tailcall := fmt.Sprintf("__tailcall%d", i)
			prog := fexitColl.Programs["fexit"+tailcall]

			if link, err := link.AttachTracing(link.TracingOptions{
				Program: prog,
			}); err != nil {
				log.Printf("Failed to attach fexit(%s): %v", tailcall, err)
				return
			} else {
				log.Printf("Attached fexit(%s)", tailcall)
				defer link.Close()
			}
		}
	}

	log.Printf("Waiting to exit... (press CTRL+C to exit)")

	<-ctx.Done()
}
