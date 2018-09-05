// Based on ssh/terminal:
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux darwin freebsd openbsd netbsd dragonfly

package log

import (
	"syscall"
	"unsafe"
)

type color byte

const (
	cBlack = iota
	cRed
	cGreen
	cYellow
	cBlue
	cMagenta
	cCyan
	cWhite
	cDefault = 9

	cNormalFg = 30
	cHighFg   = 90
	cNormalBg = 40
	cHighBg   = 100

	cBold      = "1;"
	cBlink     = "5;"
	cUnderline = "4;"
	cInverse   = "7;"
)

// IsTerminal returns whether the current descriptor attached to Stdout is an
// ANSI-compatible terminal.
func IsTerminal() bool {
	fd := syscall.Stdout
	var termios Termios
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), ioctlReadTermios, uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return err == 0
}
