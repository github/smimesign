package log

import (
	"io"
	"time"
)

var padMax = 64
var padSpaceBytes = make([]byte, padMax)
var isTTY bool

func init() {
	isTTY = IsTerminal()
	for i := 0; i < padMax; i++ {
		padSpaceBytes[i] = ' '
	}
}

// Terminal is a logging formatter that outputs terminal and developer friendly log
// entries to the given io.Writer
//
// The output of this formatter is pretty-printed and formatted for local development.
// This is a slow formatter not recommended for production use.
//
// If the attached terminal to this process is a TTY, and DisableColors is not set
// to true, the log messages will be colorized based on their level and severity.
//
// All the entries will be written to the given io.Writer. The writer *must* be
// thread safe. See: SyncedWriter
type Terminal struct {
	// If true, no terminal ANSI colors will be printed, even if the terminal
	// is a TTY.
	DisableColors bool

	// Sink will receive all log entries for writing. It *must* be thread-safe.
	// See: SyncedWriter
	Sink io.Writer
}

func (fmt *Terminal) withColor() bool {
	return isTTY && !fmt.DisableColors
}

// Log is the low-level logging interface for the Terminal formatter
func (fmt *Terminal) Log(buf []byte, lvl Level, now time.Time, message string, ctx, fields []Field) {
	buf = fmt.color(buf, cHighFg+cBlack)
	buf = append(buf, '[')
	buf = fmtTimeShort(buf, now)
	buf = append(buf, ']', ' ')
	buf = fmt.reset(buf)

	buf = fmt.color(buf, cNormalFg+lvl.Color())
	buf = append(buf, lvl.String()...)
	buf = fmt.reset(buf)

	pad1 := len(buf)
	buf = append(buf, ' ')
	buf = append(buf, message...)

	if pad := len(buf) - pad1; pad < padMax {
		buf = append(buf, padSpaceBytes[:padMax-pad]...)
	}

	for _, f := range ctx {
		buf = fmt.field(buf, f)
	}
	for _, f := range fields {
		buf = fmt.field(buf, f)
	}

	buf = append(buf, '\n')
	fmt.Sink.Write(buf)
}

func (fmt *Terminal) field(buf []byte, f Field) []byte {
	if len(buf) > 0 {
		buf = append(buf, ' ')
	}

	buf = append(buf, f.Key...)
	buf = append(buf, '=')

	buf = fmt.color(buf, cHighFg+cWhite)
	buf = fmtValue(buf, f)
	buf = fmt.reset(buf)

	return buf
}

func (fmt *Terminal) color(buf []byte, c int) []byte {
	if !fmt.withColor() {
		return buf
	}
	return append(buf, 0x1b, '[', '0'+byte(c)/10, '0'+byte(c)%10, 'm')
}

func (fmt *Terminal) reset(buf []byte) []byte {
	if !fmt.withColor() {
		return buf
	}
	return append(buf, 0x1b, '[', '0', 'm')
}
