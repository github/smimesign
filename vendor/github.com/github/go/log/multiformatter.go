package log

import "time"

// MultiFormatter returns an implementation of Formatter that dispatches Log
// calls to the provided Formatter(s). This is useful if you would like to, for
// example, send log output to two different sources.
func MultiFormatter(formatters ...Formatter) Formatter {
	return &multiFormatter{formatters}
}

type multiFormatter struct {
	formatters []Formatter
}

func (mf *multiFormatter) Log(buf []byte, lvl Level, now time.Time, msg string, ctx, fields []Field) {
	for _, f := range mf.formatters {
		f.Log(buf, lvl, now, msg, ctx, fields)
	}
}
