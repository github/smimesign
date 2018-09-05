package log

import (
	"fmt"
	"os"
)

// For tests.
var _exit = os.Exit

// StandardLogger mimics golang's standard Logger as an interface.
type StandardLogger interface {
	Print(...interface{})
	Printf(string, ...interface{})
	Println(...interface{})

	Panic(...interface{})
	Panicf(string, ...interface{})
	Panicln(...interface{})

	Fatal(...interface{})
	Fatalf(string, ...interface{})
	Fatalln(...interface{})
}

// Standardize wraps a Logger to make it compatible with the standard library.
// It takes the Logger itself, and the level to use for the StandardLogger's
// Print family of methods. If the specified Level isn't Debug, Info, Warn, or
// Error, Standardize returns ErrInvalidLevel.
func Standardize(l *Logger, lvl Level) StandardLogger {
	s := stdLogger{
		// XXX these don't actually panic or exit
		panic: l.Info,
		fatal: l.Error,
	}
	switch lvl {
	case DebugLevel:
		s.write = l.Debug
	case InfoLevel:
		s.write = l.Info
	case ErrorLevel:
		s.write = l.Error
	case DisableLogging:
		s.write = NullLogger.Info
	default:
		// default to info level
		s.write = l.Info
	}
	return &s
}

type stdLogger struct {
	write func(string, ...Field)
	panic func(string, ...Field)
	fatal func(string, ...Field)
}

// Print writes a log message at the configured log level using the default
// formats for its operands.
func (s *stdLogger) Print(args ...interface{}) {
	s.write(fmt.Sprint(args...))
}

// Printf writes a log message at the configured log level formatted according
// to a format specifier.
func (s *stdLogger) Printf(format string, args ...interface{}) {
	s.write(fmt.Sprintf(format, args...))
}

// Println writes a log message at the configured log level using the default
// formats for its operands. This is equivalent to Print since the wrapped
// Formatter determines whether to add a newline or not.
func (s *stdLogger) Println(args ...interface{}) {
	// Don't use fmt.Sprintln, since the Logger will be wrapping this
	// message in an envelope.
	s.write(fmt.Sprint(args...))
}

// Panic writes a log message at the configured log level using the default
// formats for its operands, then panics.
func (s *stdLogger) Panic(args ...interface{}) {
	msg := fmt.Sprint(args...)
	s.panic(msg)
	// Just in case the previous method didn't panic, panic here
	panic(msg)
}

// Panicf writes a log message at the configured log level formatted according
// to a format specifier, then panics.
func (s *stdLogger) Panicf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	s.panic(msg)
	panic(msg)
}

// Panicln writes a log message at the configured log level using the default
// formats for its operands, then panics. This is equivalent to Panic since the
// wrapped Formatter determines whether to add a newline or not.
func (s *stdLogger) Panicln(args ...interface{}) {
	// See Println.
	msg := fmt.Sprint(args...)
	s.panic(msg)
	panic(msg)
}

// Fatal writes a log message at the configured log level using the default
// formats for its operands, then exits.
func (s *stdLogger) Fatal(args ...interface{}) {
	s.fatal(fmt.Sprint(args...))
	// Just in case the previous method didn't exit, exit here
	_exit(1)
}

// Fatalf writes a log message at the configured log level formatted according
// to a format specifier, then exits.
func (s *stdLogger) Fatalf(format string, args ...interface{}) {
	s.fatal(fmt.Sprintf(format, args...))
	_exit(1)
}

// Fatalln writes a log message at the configured log level using the default
// formats for its operands, then exits. This is equivalent to Fatal since the
// wrapped Formatter determines whether to add a newline or not.
func (s *stdLogger) Fatalln(args ...interface{}) {
	// See Println.
	s.fatal(fmt.Sprint(args...))
	_exit(1)
}
