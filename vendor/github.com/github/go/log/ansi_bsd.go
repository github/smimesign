// +build darwin freebsd openbsd netbsd dragonfly

package log

import "syscall"

const ioctlReadTermios = syscall.TIOCGETA

type Termios syscall.Termios
