// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func main() {
	for progID, err := ebpf.ProgramGetNextID(0); err == nil; progID, err = ebpf.ProgramGetNextID(progID) {
		showProgFuncs(progID)
	}
}

func showProgFuncs(progID ebpf.ProgramID) {
	prog, err := ebpf.NewProgramFromID(progID)
	if err != nil {
		log.Printf("Failed to get program %d: %v", progID, err)
		return
	}
	defer prog.Close()

	handle, err := prog.Handle()
	if err != nil {
		log.Printf("Failed to get program handle %d: %v", progID, err)
		return
	}
	defer handle.Close()

	btfSpec, err := handle.Spec(nil)
	if err != nil {
		log.Printf("Failed to get program spec %d: %v", progID, err)
		return
	}

	var funcs []*btf.Func

	iter := btfSpec.Iterate()
	for iter.Next() {
		if fn, ok := iter.Type.(*btf.Func); ok {
			funcs = append(funcs, fn)
		}
	}

	fmt.Printf("Program %d: %s\n", progID, prog)
	for _, fn := range funcs {
		fmt.Printf("\t%s\n", fn)
	}
}
