package log

import (
	"math"
	"time"
)

// Field is a generic type that stores a key-value pair entry to be
// formatted with the log message.
type Field struct {
	// Key is the name of the key-value pair
	Key string

	// String is the string value of this entry, if the entry is a string
	Str string

	// Int is the numerical value of the entry, if the entry is a number
	Int int64

	// Any stores any other kind of values as an empty interface
	Any interface{}

	// T is the type tag for this log Field
	T byte
}

// String creates a Field that stores an string value
func String(key, val string) Field {
	return Field{T: 's', Key: key, Str: val}
}

// Errorf creates a Field storing an error message
func Errorf(val error) Field {
	return Field{T: 's', Key: "error", Str: val.Error()}
}

// Int creates a Field that stores an int value
func Int(key string, val int) Field {
	return Field{T: 'i', Key: key, Int: int64(val)}
}

// Int64 creates a Field that stores an int64 value
func Int64(key string, val int64) Field {
	return Field{T: 'i', Key: key, Int: val}
}

// Float creates a Field that stores a float64 value
func Float(key string, val float64) Field {
	return Field{T: 'f', Key: key, Int: int64(math.Float64bits(val))}
}

// Duration creates a Field that stores a time.Duration value
func Duration(key string, val time.Duration) Field {
	return Field{T: 'd', Key: key, Int: int64(val)}
}

// Time creates a Field that stores a time.Time value
func Time(key string, time time.Time) Field {
	return Field{T: 't', Key: key, Int: time.UnixNano()}
}

// Any creates a Field that can store any given value
func Any(key string, any interface{}) Field {
	return Field{T: 'a', Key: key, Any: any}
}

// LazyLogger is a callback that returns a value lazily for logging
type LazyLogger func() interface{}

// Lazy creates a logging Field that only generates the logged value
// if the log entry is going to be logged. The logged value must be
// yielded by the given callback.
//
// This is specially useful for Debug logging of data that is expensive
// to calculate.
func Lazy(key string, log LazyLogger) Field {
	return Field{T: 'l', Key: key, Any: log}
}

// CallInfo defines a field with runtime information about the call site for a
// particular logging call. When added to a logging call, the CallInfo field is
// printed in the log, with the given `key` and a value that is computed from
// the given `format` based on the location where the user is currently logging
// from. Note that this replacement is always performed at logging time, so
// CallInfo fields can be safely added to the context of a Logger with
// `Logger.Add` or `Logger.With`.
//
// `format` is an arbitrary string where the following special tokens will be
// replaced with the corresponding call information:
//
// - "{File}": the name of the current file.
// - "{Path}": the full path to the current file.
// - "{Line}": the line number for this logging call
// - "{Module}": the name of the current module
// - "{Struct}": the name of the struct acting as a receiver for the current
// method, or "" if you're logging from a global function
// - "{Method}": the name of the method being logged from, or "" if you're
// logging from a global function
// - "{Function}": the name of the current function being logged from, which
// will be either a global function, a struct method, or a closure
// - "{Namespace}": namespace is either the current struct receiver (when
// called from a method), or the current module, when called from a global
// function
func CallInfo(key string, format string) Field {
	return Field{T: 'C', Key: key, Str: format}
}

// AsFloat returns the float64 value stored in this Field, if the Field is a float
func (f *Field) AsFloat() float64 {
	return math.Float64frombits(uint64(f.Int))
}

// AsDuration returns the time.Duration value stored in this field, if the field is a duration
func (f *Field) AsDuration() time.Duration {
	return time.Duration(int64(f.Int))
}

// AsTime returns the time.Time duration stored in this field, if the field is a time
func (f *Field) AsTime() time.Time {
	return time.Unix(f.Int/1e9, f.Int%1e9)
}

// LazyValue returns the lazily-computated value stored in this field
func (f *Field) LazyValue() interface{} {
	return f.Any.(LazyLogger)()
}
