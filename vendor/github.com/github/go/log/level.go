package log

import "strings"

// Level defines the logging granularity for log messages.
// A 'Debug' level on a Logger will log all messages, including
// 'Debug' ones. An 'Info' level will only log 'Info' and 'Error'
// messages, and so on.
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	ErrorLevel
	DisableLogging
)

// Color returns an ANSI terminal color to be used for log entries with this level
func (lvl Level) Color() int {
	switch lvl {
	case DebugLevel:
		return cWhite
	case InfoLevel:
		return cBlue
	case ErrorLevel:
		return cRed
	default:
		return 0
	}
}

// String returns a textual representation of the logging level
func (lvl Level) String() string {
	switch lvl {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return " INFO"
	case ErrorLevel:
		return "ERROR"
	default:
		return ""
	}
}

// LevelFromString returns a logging level from a string description
func LevelFromString(s string) Level {
	switch strings.ToLower(s) {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "error":
		return ErrorLevel
	case "disable":
		return DisableLogging
	default:
		// Unrecognised string, so default to 'Info'
		return InfoLevel
	}
}
