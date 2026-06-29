// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"internal/assert"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp ./xdp.c -- -g -D__TARGET_ARCH_x86 -I../headers -Wall

func findStartIndex(prog *ebpf.ProgramSpec, stub string) (int, bool) {
	for i := 0; i < len(prog.Instructions); i++ {
		if symbol := prog.Instructions[i].Symbol(); symbol == stub {
			return i, true
		}
	}
	return -1, false
}

func findEndIndex(prog *ebpf.ProgramSpec, start int) int {
	idx := start + 1
	for ; idx < len(prog.Instructions); idx++ {
		if prog.Instructions[idx].Symbol() != "" {
			break
		}
	}
	return idx - 1
}

func injectInsns(prog *ebpf.ProgramSpec, stub string, insns asm.Instructions) {
	injIdx, ok := findStartIndex(prog, stub)
	if !ok {
		return
	}

	endIdx := findEndIndex(prog, injIdx)

	if len(insns) != 0 {
		insns[0] = insns[0].WithMetadata(prog.Instructions[injIdx].Metadata)
	}
	prog.Instructions = append(prog.Instructions[:injIdx],
		append(insns, prog.Instructions[endIdx+1:]...)...)
}

func Ja(offset int16) asm.Instruction {
	return asm.Instruction{
		OpCode: asm.Ja.Op(asm.ImmSource),
		Offset: offset,
	}
}

func clearSubprog(prog *ebpf.ProgramSpec, stub string) {
	injectInsns(prog, stub, nil)

	for i := 0; i < len(prog.Instructions); i++ {
		if ref := prog.Instructions[i].Reference(); ref == stub {
			prog.Instructions[i] = Ja(0)
		}
	}
}

func main() {
	var eliminate bool
	flag.BoolVarP(&eliminate, "eliminate", "e", false, "Eliminate the subprog")
	flag.Parse()

	ifi, err := netlink.LinkByName("lo")
	assert.NoErr(err, "Failed to find lo: %v")

	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadXdp()
	assert.NoErr(err, "Failed to load xdp bpf spec: %v")

	if eliminate {
		clearSubprog(spec.Programs["xdp_fn"], "subprog")
	}

	coll, err := ebpf.NewCollection(spec)
	assert.NoVerifierErr(err, "Failed to new coll: %v")

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["xdp_fn"],
		Interface: ifi.Attrs().Index,
	})
	assert.NoErr(err, "Failed to attach xdp(%s)", "lo")
	defer l.Close()

	log.Printf("Attached xdp to %s", "lo")

	<-ctx.Done()
}
