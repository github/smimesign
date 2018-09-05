package log

import (
	gofmt "fmt"
	"io"
	"strconv"
	"time"
)

// Logfmt is a logging formatter that outputs "logfmt" formatted entries
// to the given io.Writer
//
// Logfmt is a loosely defined logging format (see https://brandur.org/logfmt)
// for structured data, which plays very well with indexing tools like Splunk
//
// A logfmt-formatted entry looks like this:
//
//	time=2006-01-02T15:04:05Z07:00 msg="this is a message" key=val int=42 key2="val with word" float=33.33
type Logfmt struct {
	// Sink will receive all log entries for writing. It *must* be thread-safe.
	// See: SyncedWriter
	Sink io.Writer
}

var (
	keyTimestamp = "time="
	keyMessage   = "msg="
)

// Log is the low-level logging interface for the logfmt formatter
func (fmt *Logfmt) Log(buf []byte, lvl Level, now time.Time, message string, ctx, fields []Field) {
	buf = append(buf, keyTimestamp...)
	buf = fmtTime(buf, now)

	buf = append(buf, ' ')
	buf = append(buf, keyMessage...)
	buf = fmtString(buf, message)

	if len(ctx)+len(fields) > 0 {
		buf = append(buf, ' ')
		for _, f := range ctx {
			buf = fmtField(buf, f)
			buf = append(buf, ' ')
		}
		for _, f := range fields {
			buf = fmtField(buf, f)
			buf = append(buf, ' ')
		}
		buf = buf[:len(buf)-1]
	}

	buf = append(buf, '\n')
	fmt.Sink.Write(buf)
}

func fmtField(buf []byte, f Field) []byte {
	buf = append(buf, f.Key...)
	buf = append(buf, '=')
	return fmtValue(buf, f)
}

func fmtTime(b []byte, t time.Time) []byte {
	t = t.UTC()
	yy, mm, dd := t.Date()
	hh, mn, ss := t.Clock()

	return append(b,
		byte('0'+yy/1000), byte('0'+(yy/100)%10), byte('0'+(yy/10)%10), byte('0'+yy%10), '-',
		byte('0'+mm/10), byte('0'+mm%10), '-',
		byte('0'+dd/10), byte('0'+dd%10), 'T',
		byte('0'+hh/10), byte('0'+hh%10), ':',
		byte('0'+mn/10), byte('0'+mn%10), ':',
		byte('0'+ss/10), byte('0'+ss%10), 'Z')
}

func fmtTimeShort(b []byte, t time.Time) []byte {
	hh, mn, ss := t.Clock()
	return append(b,
		byte('0'+hh/10), byte('0'+hh%10), ':',
		byte('0'+mn/10), byte('0'+mn%10), ':',
		byte('0'+ss/10), byte('0'+ss%10))
}

func fmtValue(buf []byte, f Field) []byte {
	switch f.T {
	case 'i':
		buf = strconv.AppendInt(buf, f.Int, 10)

	case 's':
		buf = fmtString(buf, f.Str)

	case 'f':
		buf = strconv.AppendFloat(buf, f.AsFloat(), 'g', 8, 64)

	case 'd':
		buf = append(buf, f.AsDuration().String()...)

	case 't':
		buf = fmtTime(buf, f.AsTime())

	case 'a':
		buf = fmtAny(buf, f.Any)

	case 'l':
		buf = fmtAny(buf, f.LazyValue())
	}

	return buf
}

func fmtAny(buf []byte, any interface{}) []byte {
	switch str := any.(type) {
	case gofmt.Stringer:
		return fmtString(buf, str.String())
	case gofmt.GoStringer:
		return fmtString(buf, str.GoString())
	default:
		return fmtString(buf, gofmt.Sprint(str))
	}
}

func fmtString(b []byte, str string) []byte {
	quote := false
	escape := false

	for i := 0; i < len(str); i++ {
		switch str[i] {
		case ' ', '\t':
			quote = true
		case '"', '\r', '\n':
			escape = true
		}
	}

	if escape {
		b = strconv.AppendQuote(b, str)
	} else if quote {
		b = append(b, '"')
		b = append(b, str...)
		b = append(b, '"')
	} else {
		b = append(b, str...)
	}

	return b
}
