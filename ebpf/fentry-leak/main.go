// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"internal/pkg/bpf"
	"internal/pkg/errx"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp ./xdp.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach XDP program")
	flag.Parse()

	err := rlimit.RemoveMemlock()
	errx.Check(err, "Failed to remove memlock")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadXdp()
	errx.Check(err, "Failed to load xdp bpf spec")

	xdpDummy := spec.Programs["dummy"]
	dummyProg, err := ebpf.NewProgram(xdpDummy)
	errx.Check(err, "Failed to create dummy program")
	defer dummyProg.Close()

	// get function name by dummy program
	funcName, err := bpf.GetProgEntryFuncName(dummyProg)
	errx.Check(err, "Failed to get function name")

	log.Printf("XDP function name: %s", funcName)

	spec = spec.Copy()
	xdpFentry := spec.Programs["fentry_xdp"]
	xdpFentry.AttachTarget = dummyProg
	xdpFentry.AttachTo = funcName

	var obj xdpObjects
	errx.CheckVerifierErr(spec.LoadAndAssign(&obj, nil), "Failed to load and assign fentry objects")
	defer obj.Close()

	spec = spec.Copy()
	xdpFentry = spec.Programs["fentry_xdp"]
	xdpFentry.AttachTarget = dummyProg
	xdpFentry.AttachTo = funcName

	var leak xdpObjects
	errx.CheckVerifierErr(spec.LoadAndAssign(&leak, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"jmp_table": obj.JmpTable,
		},
	}), "Failed to load and assign leak objects")
	defer leak.Close()

	err = obj.JmpTable.Put(uint32(0), leak.FentryXdp)
	errx.Check(err, "Failed to put jmp table")

	// No leak, because jmp_table is protected by uref, '.map_release_uref = prog_array_map_clear,'.

	log.Printf("Ctrl-C to check leak FDs..")

	<-ctx.Done()
}
