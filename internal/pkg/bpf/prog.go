// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// GetProgEntryFuncName returns the name of the entry function in the program.
func GetProgEntryFuncName(prog *ebpf.Program) (string, error) {
	btfHandle, err := prog.Handle()
	if err != nil {
		return "", fmt.Errorf("failed to get prog handle: %w", err)
	}

	btfSpec, err := btfHandle.Spec(nil)
	if err != nil {
		return "", fmt.Errorf("failed to get prog BTF spec: %w", err)
	}

	iter := btfSpec.Iterate()
	for iter.Next() {
		fn, ok := iter.Type.(*btf.Func)
		if ok {
			return fn.Name, nil
		}
	}

	return "", fmt.Errorf("failed to find function in prog BTF spec")
}
