package log

import (
	"sync"
	"sync/atomic"
	"time"
)

const bufferCap = 512

var buffers = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, bufferCap)
	},
}

// Formatter is the low level interface to format and output
// log entries.
type Formatter interface {
	Log(buf []byte, lvl Level, now time.Time, msg string, ctx, fields []Field)
}

var defaultFormatter = &Logfmt{Sink: Stdout}

// NullLogger is a Logger instance that discards all input
var NullLogger = New(DisableLogging, nil)

// DefaultLogger gives a globally accessible Logger
var DefaultLogger = New(InfoLevel, nil)

type baseLogger struct {
	// Level is the logging level for this Logger. It can be one of
	// 'Debug', 'Info' or 'Error'. Only log entries with an equal
	// or higher level to this will be logged.
	Level Level

	// Format is the actual logger implementation. It controls the format
	// of the log entries and where are they written to.
	Format Formatter

	ownBuf int32
	buf    []byte
}

// Logger is the main logging struct for this package. It provides the
// high-level logging API for the user, which relays the log entries
// to the relevant Formatter
type Logger struct {
	*baseLogger
	ctx context
}

// New returns a new logger instance with the given logging level and
// formatter.
func New(lvl Level, fmt Formatter) *Logger {
	return &Logger{
		baseLogger: &baseLogger{
			Level:  lvl,
			Format: fmt,
		},
	}
}

// logCallstackDepth is the stack depth of a log call, used when looking up
// the caller information as to point to the original callsite on the user's
// program
const logCallstackDepth = 4

type context []Field

func (ctx context) dynamicFields() bool {
	for _, f := range ctx {
		if f.T == 'C' {
			return true
		}
	}
	return false
}

func (ctx context) expand(info *callInfo) *callInfo {
	for i, f := range ctx {
		if f.T == 'C' {
			if info == nil {
				info = newCallInfo(logCallstackDepth)
			}
			ctx[i] = String(f.Key, info.Format(f.Str))
		}
	}
	return info
}

func (l *baseLogger) log(lvl Level, msg string, ctx context, fields ...Field) {
	if l.Level > lvl {
		return
	}

	// Fast path: if we've locked the `ownBuf` spinlock, we can use the default
	// buffer for this logger. If we failed to lock it, we don't spin, instead
	// we fall back to picking up a scratch buffer from our buffer pool
	var buf []byte
	own := atomic.CompareAndSwapInt32(&l.ownBuf, 0, 1)
	if own {
		if l.buf == nil {
			l.buf = make([]byte, 0, bufferCap)
		}
		buf = l.buf[:0]
	} else {
		buf = buffers.Get().([]byte)
	}

	var info *callInfo
	if ctx.dynamicFields() {
		ctx = append(context(nil), ctx...)
		info = ctx.expand(info)
	}
	info = context(fields).expand(info)

	now := time.Now()
	if l.Format == nil {
		defaultFormatter.Log(buf, lvl, now, msg, ctx, fields)
	} else {
		l.Format.Log(buf, lvl, now, msg, ctx, fields)
	}

	if own {
		atomic.StoreInt32(&l.ownBuf, 0)
	} else {
		buffers.Put(buf[:0])
	}
}

// Debug logs a debug entry with the given message and fields
func (l *Logger) Debug(msg string, fields ...Field) {
	l.log(DebugLevel, msg, l.ctx, fields...)
}

// Info logs an info entry with the given message and fields
func (l *Logger) Info(msg string, fields ...Field) {
	l.log(InfoLevel, msg, l.ctx, fields...)
}

// Error logs an error entry with the given message and fields
func (l *Logger) Error(msg string, fields ...Field) {
	l.log(ErrorLevel, msg, l.ctx, fields...)
}

// Add records additional default fields in this Logger
func (l *Logger) Add(fields ...Field) {
	l.ctx = append(l.ctx, fields...)
}

// With creates a child logger based off this one. All entries
// logged with the returned Logger will contain by default the
// given fields.
func (l *Logger) With(fields ...Field) *Logger {
	ctx := make(context, 0, len(l.ctx)+len(fields))
	ctx = append(ctx, l.ctx...)
	ctx = append(ctx, fields...)
	return &Logger{baseLogger: l.baseLogger, ctx: ctx}
}

// Debug logs a Debug message with the DefaultLogger instance
func Debug(msg string, fields ...Field) {
	DefaultLogger.log(DebugLevel, msg, DefaultLogger.ctx, fields...)
}

// Info logs an Info message with the DefaultLogger instance
func Info(msg string, fields ...Field) {
	DefaultLogger.log(InfoLevel, msg, DefaultLogger.ctx, fields...)
}

// Error logs an Error message with the DefaultLogger instance
func Error(msg string, fields ...Field) {
	DefaultLogger.log(ErrorLevel, msg, DefaultLogger.ctx, fields...)
}

// With creates an instance of the DefaultLogger with the given fields
func With(fields ...Field) *Logger {
	return DefaultLogger.With(fields...)
}
