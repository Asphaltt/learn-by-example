// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

package xdp

type Action uint8

const (
	ActionAborted Action = iota
	ActionDrop
	ActionPass
	ActionTx
	ActionRedirect
)

func (a Action) String() string {
	switch a {
	case ActionAborted:
		return "XDP_ABORTED"
	case ActionDrop:
		return "XDP_DROP"
	case ActionPass:
		return "XDP_PASS"
	case ActionTx:
		return "XDP_TX"
	case ActionRedirect:
		return "XDP_REDIRECT"
	default:
		return "XDP_UNKNOWN"
	}
}
