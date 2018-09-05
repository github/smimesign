package log

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLogfmtFormatter(t *testing.T) {
	buf := &bytes.Buffer{}
	formatter := &Logfmt{
		Sink: &SyncedWriter{Writer: buf},
	}

	fields1 := []Field{String("key", "val"), Int("int", 42)}
	fields2 := []Field{String("key", "val with word"), Float("float", 33.33)}

	now := time.Now()
	nowstr := now.UTC().Format(time.RFC3339)
	var expected string

	formatter.Log(nil, DebugLevel, now, "this is a message", nil, nil)
	expected = fmt.Sprintf("time=%s msg=\"this is a message\"\n", nowstr)
	assert.Equal(t, expected, buf.String())
	buf.Reset()

	formatter.Log(nil, DebugLevel, now, "singleword", nil, nil)
	expected = fmt.Sprintf("time=%s msg=singleword\n", nowstr)
	assert.Equal(t, expected, buf.String())
	buf.Reset()

	formatter.Log([]byte("FOOBAR "), DebugLevel, now, "singleword", nil, nil)
	expected = fmt.Sprintf("FOOBAR time=%s msg=singleword\n", nowstr)
	assert.Equal(t, expected, buf.String())
	buf.Reset()

	formatter.Log(nil, DebugLevel, now, "singleword", fields1, nil)
	expected = fmt.Sprintf("time=%s msg=singleword key=val int=42\n", nowstr)
	assert.Equal(t, expected, buf.String())
	buf.Reset()

	formatter.Log(nil, DebugLevel, now, "singleword", nil, fields1)
	expected = fmt.Sprintf("time=%s msg=singleword key=val int=42\n", nowstr)
	assert.Equal(t, expected, buf.String())
	buf.Reset()

	formatter.Log(nil, DebugLevel, now, "singleword", fields1, fields1)
	expected = fmt.Sprintf("time=%s msg=singleword key=val int=42 key=val int=42\n", nowstr)
	assert.Equal(t, expected, buf.String())
	buf.Reset()

	formatter.Log(nil, DebugLevel, now, "singleword", fields1, fields2)
	expected = fmt.Sprintf("time=%s msg=singleword key=val int=42 key=\"val with word\" float=33.33\n", nowstr)
	assert.Equal(t, expected, buf.String())
	buf.Reset()
}

func TestLogfmtString(t *testing.T) {
	assertStr := func(expected, str string) {
		assert.Equal(t, expected, string(fmtString(nil, str)))
	}

	assertStr(`foobar`, `foobar`)
	assertStr(`"foobar baz"`, `foobar baz`)
	assertStr("\"foobar\tbaz\"", "foobar\tbaz")
	assertStr("\"foobar \\\"baz\\\"\"", `foobar "baz"`)
	assertStr("\"foobar\\nbaz\"", "foobar\nbaz")
	assertStr("\"foobar\\r\\nbaz\"", "foobar\r\nbaz")
}

func TestLogfmtNumbers(t *testing.T) {
	assertInt := func(num int) {
		expected := fmt.Sprintf("%d", num)
		field := Int("", num)
		assert.Equal(t, expected, string(fmtValue(nil, field)))
	}

	assertFloat := func(num float64) {
		expected := fmt.Sprintf("%g", num)
		field := Float("", num)
		assert.Equal(t, expected, string(fmtValue(nil, field)))
	}

	assertInt(0)
	assertInt(42)
	assertInt(123456789)
	assertInt(4242)

	assertFloat(0)
	assertFloat(0.2323)
	assertFloat(42.42)
	assertFloat(12345.22)
}
