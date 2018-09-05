package log

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func BenchmarkAllocationsLogfmt(b *testing.B) {
	fmt := Logfmt{Sink: ioutil.Discard}
	logger := New(InfoLevel, &fmt)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.Info("hello world", String("foobar", "baz"), Int("loop", 13))
		}
	})
}

func BenchmarkAllocationsTerminal(b *testing.B) {
	fmt := Terminal{Sink: ioutil.Discard}
	logger := New(InfoLevel, &fmt)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.Info("hello world", String("foobar", "baz"), Int("loop", 13))
		}
	})
}

func getAllLines(buf *bytes.Buffer) []string {
	lines := strings.Split(buf.String(), "\n")
	return lines[:len(lines)-1]
}

func TestLogfmt(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(
		DebugLevel,
		&Logfmt{Sink: &SyncedWriter{Writer: buf}},
	)

	for i := 0; i < 20; i++ {
		logger.Info("hello world", String("foobar", "baz"), Int("loop", i))
		logger.Debug("hello world", String("foobar", "baz"), Int("loop", i))
		logger.Error("hello world", String("foobar", "baz"), Int("loop", i))
	}

	lines := getAllLines(buf)
	assert.Equal(t, 60, len(lines))
	for n, line := range lines {
		assert.Contains(t, line, `msg="hello world"`)
		assert.Contains(t, line, `foobar=baz`)
		assert.Contains(t, line, fmt.Sprintf("loop=%d", n/3))
	}
}

func TestDefaultLogfmt(t *testing.T) {
	buf := &bytes.Buffer{}
	DefaultLogger.Format = &Logfmt{
		Sink: &SyncedWriter{Writer: buf},
	}

	for i := 0; i < 20; i++ {
		Info("hello world", String("foobar", "baz"), Int("loop", i))
		Debug("hello world", String("foobar", "baz"), Int("loop", i))
		Error("hello world", String("foobar", "baz"), Int("loop", i))
	}

	lines := getAllLines(buf)
	assert.Equal(t, 40, len(lines))
	for n, line := range lines {
		assert.Contains(t, line, `msg="hello world"`)
		assert.Contains(t, line, `foobar=baz`)
		assert.Contains(t, line, fmt.Sprintf("loop=%d", n/2))
	}
}

func TestDefaultLogfmtDebug(t *testing.T) {
	buf := &bytes.Buffer{}
	DefaultLogger.Format = &Logfmt{
		Sink: &SyncedWriter{Writer: buf},
	}
	DefaultLogger.Level = DebugLevel

	for i := 0; i < 20; i++ {
		Info("hello world", String("foobar", "baz"), Int("loop", i))
		Debug("hello world", String("foobar", "baz"), Int("loop", i))
		Error("hello world", String("foobar", "baz"), Int("loop", i))
	}

	lines := getAllLines(buf)

	// Debug entries should now appear
	assert.Equal(t, 60, len(lines))
}

func TestDefaultLogAdd(t *testing.T) {
	buf := &bytes.Buffer{}
	DefaultLogger.Format = &Logfmt{
		Sink: &SyncedWriter{Writer: buf},
	}
	DefaultLogger.Add(String("foobar", "baz"), Int("limit", 20))

	for i := 0; i < 20; i++ {
		Debug("hello world", Int("loop", i))
		Error("hello world", Int("loop", i))
	}

	lines := getAllLines(buf)
	assert.Equal(t, 40, len(lines))
	for n, line := range lines {
		assert.Contains(t, line, `msg="hello world"`)
		assert.Contains(t, line, `foobar=baz`)
		assert.Contains(t, line, `limit=20`)
		assert.Contains(t, line, fmt.Sprintf("loop=%d", n/2))
	}
}

func stripTime(line string) string {
	idx := strings.IndexByte(line, ' ')
	return line[idx+1 : len(line)]
}

func TestChildContexts(t *testing.T) {
	buf := &bytes.Buffer{}
	l1 := New(DebugLevel, &Logfmt{Sink: &SyncedWriter{Writer: buf}})

	l2 := l1.With(String("key1", "1"))
	l2.Level = InfoLevel

	l3 := l2.With(String("key2", "2"), Int("key3", 3))
	l3.Level = ErrorLevel

	assert.Equal(t, ErrorLevel, l1.Level)

	assert.Equal(t, 1, len(l2.ctx))
	assert.Equal(t, ErrorLevel, l2.Level)

	assert.Equal(t, 3, len(l3.ctx))
	assert.Equal(t, ErrorLevel, l3.Level)

	l1.Error("l1 log", String("foobar", "baz"), Int("loop", 1))
	l2.Error("l2 log", String("foobar", "baz"), Int("loop", 2))
	l3.Error("l3 log", String("foobar", "baz"), Int("loop", 3))

	lines := getAllLines(buf)
	assert.Equal(t, 3, len(lines))

	assert.Equal(t,
		`msg="l1 log" foobar=baz loop=1`,
		stripTime(lines[0]))

	assert.Equal(t,
		`msg="l2 log" key1=1 foobar=baz loop=2`,
		stripTime(lines[1]))

	assert.Equal(t,
		`msg="l3 log" key1=1 key2=2 key3=3 foobar=baz loop=3`,
		stripTime(lines[2]))
}

func ExampleLogger() {
	logger := New(DebugLevel, &Logfmt{Sink: Stdout})

	logger.Debug("this is a debug message", String("foobar", "baz"), Int("loop", 0))
	logger.Info("this is an information message", String("host", "localhost"), Int("requests", 23))
	logger.Error("this is an error message", String("class", "BadError"), Duration("req_duration", 200))
}
