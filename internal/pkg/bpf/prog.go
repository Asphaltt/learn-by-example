// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// GetFuncName returns the name of the very first function in the program.
func GetFuncName(prog *ebpf.Program) (string, error) {
	progInfo, err := prog.Info()
	if err != nil {
		return "", fmt.Errorf("failed to get prog info: %w", err)
	}
	progInsns, err := progInfo.Instructions()
	if err != nil {
		return "", fmt.Errorf("failed to get instructions: %w", err)
	}
	funcName := progInsns.Name()
	if funcName == "" {
		return "", errors.New("failed to get function name")
	}

	return funcName, nil
}
