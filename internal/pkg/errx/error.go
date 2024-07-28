// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package errx

import (
	"errors"
	"log"

	"github.com/cilium/ebpf"
)

func Check(err error, format string, args ...interface{}) {
	if err != nil {
		args = append(args, err)
		log.Fatalf(format+": %v", args...)
	}
}

func CheckVerifierErr(err error, format string, args ...interface{}) {
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Verifier error: %+v", ve)
		}
		args = append(args, err)
		log.Fatalf(format+": %v", args...)
	}
}

func Must[T any](x T, err error) T {
	Check(err, "Error")
	return x
}
