// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package errx

import (
	"errors"
	"log"
	"strings"

	"github.com/cilium/ebpf"
)

func Check(err error, format string, args ...interface{}) {
	if err != nil {
		args = append(args, err)
		if strings.HasSuffix(format, ": %v") {
			log.Fatalf(format, args...)
		} else {
			log.Fatalf(format+": %v", args...)
		}
	}
}

func CheckVerifierErr(err error, format string, args ...interface{}) {
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Verifier error: %+v", ve)
		}
		Check(err, format, args...)
	}
}

func Must[T any](x T, err error) T {
	Check(err, "Error")
	return x
}
