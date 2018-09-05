package log

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type stubbedExit struct {
	Status *int
}

func (se *stubbedExit) UnstubExit() {
	_exit = os.Exit
}

func (se *stubbedExit) AssertExit(t testing.TB) {
	if assert.NotNil(t, se.Status, "Expected to exit.") {
		assert.Equal(t, 1, *se.Status, "Unexpected exit code.")
	}
}

func stubExit() *stubbedExit {
	stub := &stubbedExit{}
	_exit = func(s int) { stub.Status = &s }
	return stub
}

func newStd(lvl Level) (StandardLogger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	fmt := &Terminal{DisableColors: true, Sink: buf}
	logger := New(DebugLevel, fmt)
	std := Standardize(logger, lvl)
	return std, buf
}

func TestStandardizeUnknownLevel(t *testing.T) {
	lvl := Level(42)
	std, buf := newStd(lvl)
	std.Print("foo")
	assert.Contains(t, buf.String(), "INFO foo", "Print logged at an unexpected level.")
	buf.Reset()
}

func TestStandardizeValidLevels(t *testing.T) {
	for _, lvl := range []Level{DebugLevel, InfoLevel, ErrorLevel} {
		std, buf := newStd(lvl)
		std.Print("foo")
		expectation := fmt.Sprintf(`%s foo`, lvl.String())
		assert.Contains(t, buf.String(), expectation, "Print logged at an unexpected level.")
		buf.Reset()
	}
}

func TestDisableLoggingLevel(t *testing.T) {
	std, buf := newStd(DisableLogging)
	std.Print("foo")
	assert.Empty(t, buf.String())
	buf.Reset()
}

func TestStandardLoggerPrint(t *testing.T) {
	std, buf := newStd(InfoLevel)

	verify := func() {
		assert.Contains(t, buf.String(), `foo 42`, "Unexpected output from Print-family method.")
		buf.Reset()
	}

	std.Print("foo ", 42)
	verify()

	std.Printf("foo %d", 42)
	verify()

	std.Println("foo ", 42)
	verify()
}

func TestStandardLoggerPanic(t *testing.T) {
	std, buf := newStd(InfoLevel)

	verify := func(f func()) {
		assert.Panics(t, f, "Expected calls to Panic methods to panic.")
		assert.Contains(t, buf.String(), `foo 42`, "Unexpected output from Panic-family method.")
		buf.Reset()
	}

	verify(func() {
		std.Panic("foo ", 42)
	})

	verify(func() {
		std.Panicf("foo %d", 42)
	})

	verify(func() {
		std.Panicln("foo ", 42)
	})
}

func TestStandardLoggerFatal(t *testing.T) {
	std, buf := newStd(InfoLevel)

	verify := func(f func()) {
		stub := stubExit()
		f()
		assert.Contains(t, buf.String(), `foo 42`, "Unexpected output from Fatal-family method.")
		stub.AssertExit(t)
		stub.UnstubExit()
		buf.Reset()
	}

	verify(func() {
		std.Fatal("foo ", 42)
	})

	verify(func() {
		std.Fatalf("foo %d", 42)
	})

	verify(func() {
		std.Fatalln("foo ", 42)
	})
}
