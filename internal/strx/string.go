// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package strx

import "unsafe"

func NullTerminated(b []byte) string {
	var idx int
	for idx = 0; idx < len(b) && b[idx] != 0; idx++ {
	}
	if idx == 0 {
		return ""
	}
	return unsafe.String(&b[0], idx)
}
