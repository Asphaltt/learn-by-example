// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: MIT

package endx

func Htons(n uint16) uint16 {
	return (n&0x00ff)<<8 | (n&0xff00)>>8
}

func Htonl(n uint32) uint32 {
	return (n&0x000000ff)<<24 | (n&0x0000ff00)<<8 | (n&0x00ff0000)>>8 | (n&0xff000000)>>24
}
