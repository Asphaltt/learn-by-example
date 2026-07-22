// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"internal/assert"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fexit ./fexit.c -- -D__TARGET_ARCH_x86 -I../headers -Wall -g

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove memlock: %v")

	ifi, err := net.InterfaceByName("lo")
	assert.NoErr(err, "Failed to find lo dev: %v")

	spec, err := loadFexit()
	assert.NoErr(err, "Failed to load spec: %v")
	delete(spec.Programs, "trace1")

	coll, err := ebpf.NewCollection(spec)
	assert.NoVerifierErr(err, "Failed to create coll: %v")
	defer coll.Close()

	xdp, err := link.AttachXDP(link.XDPOptions{
		Interface: ifi.Index,
		Program:   coll.Programs["xdp_main"],
	})
	assert.NoErr(err, "Failed to attach xdp(xdp_main) to lo: %v")
	defer xdp.Close()

	spec, err = loadFexit()
	assert.NoErr(err, "Failed to load spec: %v")
	delete(spec.Programs, "xdp_main")
	delete(spec.Maps, "pa")

	prog := spec.Programs["trace1"]
	prog.AttachTarget = coll.Programs["xdp_main"]
	prog.AttachTo = "xdp_main"

	coll, err = ebpf.NewCollection(spec)
	assert.NoVerifierErr(err, "Failed to create coll: %v")
	defer coll.Close()

	fexit, err := link.AttachTracing(link.TracingOptions{
		Program:    coll.Programs["trace1"],
		AttachType: ebpf.AttachTraceFExit,
	})
	assert.NoErr(err, "Failed to attach to fentry(xdp_main): %v")

	coll, err = ebpf.NewCollection(spec)
	assert.NoVerifierErr(err, "Failed to create coll: %v")
	defer coll.Close()

	err = fexit.Close()
	assert.NoErr(err, "Failed to detach fentry: %v")

	log.Println("END")
}
