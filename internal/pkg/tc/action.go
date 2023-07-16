// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

package tc

type Action int8

const (
	ActionUnspec Action = -1 + iota
	ActionOk
	ActionReclassify
	ActionShot
	ActionPipe
	ActionStolen
	ActionQueued
	ActionRepeat
	ActionRedirect
	ActionTrap
)

func (a Action) String() string {
	switch a {
	case ActionUnspec:
		return "TC_ACT_UNSPEC"
	case ActionOk:
		return "TC_ACT_OK"
	case ActionReclassify:
		return "TC_ACT_RECLASSIFY"
	case ActionShot:
		return "TC_ACT_SHOT"
	case ActionPipe:
		return "TC_ACT_PIPE"
	case ActionStolen:
		return "TC_ACT_STOLEN"
	case ActionQueued:
		return "TC_ACT_QUEUED"
	case ActionRepeat:
		return "TC_ACT_REPEAT"
	case ActionRedirect:
		return "TC_ACT_REDIRECT"
	case ActionTrap:
		return "TC_ACT_TRAP"
	default:
		return "TC_ACT_UNSPEC"
	}
}
