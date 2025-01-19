// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package assert

import (
	"errors"
	"log"

	"github.com/cilium/ebpf"
)

func NoErr(err error, msg string, args ...any) {
	if err != nil {
		args = append(args, err)
		log.Fatalf(msg, args...)
	}
}

func NoVerifierErr(err error, msg string, args ...any) {
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Printf("Verifier log:\n%+v", verr)
		}
		args = append(args, err)
		log.Fatalf(msg, args...)
	}
}

func Equal[T comparable](a, b T, msg string, args ...any) {
	if a != b {
		log.Fatalf(msg, args...)
	}
}

func True(cond bool, msg string, args ...any) {
	if !cond {
		log.Fatalf(msg, args...)
	}
}

func False(cond bool, msg string, args ...any) {
	if cond {
		log.Fatalf(msg, args...)
	}
}

func SliceNotEmpty[T any](s []T, msg string, args ...any) {
	if len(s) == 0 {
		log.Fatalf(msg, args...)
	}
}

func SliceLen[T any](s []T, l int, msg string, args ...any) {
	if len(s) != l {
		log.Fatalf(msg, args...)
	}
}
