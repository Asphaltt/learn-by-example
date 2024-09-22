// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

package bpf

import (
	"errors"
	"fmt"

	"internal/pkg/errx"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// GetProgEntryFuncName returns the name of the entry function in the program.
func GetProgEntryFuncName(prog *ebpf.Program) (string, error) {
	info, err := prog.Info()
	if err != nil {
		return "", fmt.Errorf("failed to get program info: %w", err)
	}

	if _, ok := info.BTFID(); !ok {
		return "", fmt.Errorf("program does not have BTF ID")
	}

	insns, err := info.Instructions()
	if err != nil {
		return "", fmt.Errorf("failed to get program instructions: %w", err)
	}

	for _, insn := range insns {
		if sym := insn.Symbol(); sym != "" {
			return sym, nil
		}
	}

	return "", fmt.Errorf("no entry function found in program")
}

func ListProgs(typ ebpf.ProgramType) ([]*ebpf.Program, error) {
	var (
		id  ebpf.ProgramID
		err error
	)

	var progs []*ebpf.Program
	for id, err = ebpf.ProgramGetNextID(id); err == nil; id, err = ebpf.ProgramGetNextID(id) {
		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			return nil, err
		}

		if prog.Type() == typ {
			progs = append(progs, prog)
		} else {
			_ = prog.Close()
		}
	}

	if !errors.Is(err, unix.ENOENT) { //  err != nil always
		return nil, err
	}

	return progs, nil
}

func Load(obj any, load func(obj any, opts *ebpf.CollectionOptions) error) {
	errx.CheckVerifierErr(load(obj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:    ebpf.LogLevelInstruction | ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogDisabled: false,
		},
	}), "Failed to load bpf objects")
}

func LoadWithSpec(spec *ebpf.CollectionSpec, obj any) {
	errx.CheckVerifierErr(spec.LoadAndAssign(obj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:    ebpf.LogLevelInstruction | ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogDisabled: false,
		},
	}), "Failed to load bpf objects")
}
