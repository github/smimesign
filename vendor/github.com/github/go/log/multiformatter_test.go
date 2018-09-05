package log

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMultiFormatterDispatch(t *testing.T) {
	fmtA := &formatterDouble{}
	fmtB := &formatterDouble{}

	multi := MultiFormatter(fmtA, fmtB)
	logger := New(InfoLevel, multi)

	logger.Info("msg-1")
	logger.Info("msg-2")

	assert.Equal(t, []string{"msg-1", "msg-2"}, fmtA.msgs())
	assert.Equal(t, []string{"msg-1", "msg-2"}, fmtB.msgs())
}

func TestMultiFormatterCalls(t *testing.T) {
	target := &formatterDouble{}
	multi := MultiFormatter(target)

	c := logCall{
		buf:    []byte{'b'},
		lvl:    InfoLevel,
		now:    time.Now(),
		msg:    "msg",
		ctx:    []Field{String("ctx", "f1")},
		fields: []Field{String("fields", "f2")},
	}

	multi.Log(c.buf, c.lvl, c.now, c.msg, c.ctx, c.fields)

	assert.Len(t, target.calls, 1)
	assert.Equal(t, c, target.calls[0])
}

type formatterDouble struct {
	calls []logCall
}

func (f formatterDouble) msgs() []string {
	var msgs []string

	for _, call := range f.calls {
		msgs = append(msgs, call.msg)
	}

	return msgs
}

type logCall struct {
	buf    []byte
	lvl    Level
	now    time.Time
	msg    string
	ctx    []Field
	fields []Field
}

func (f *formatterDouble) Log(buf []byte, lvl Level, now time.Time, msg string, ctx, fields []Field) {
	f.calls = append(f.calls, logCall{buf, lvl, now, msg, ctx, fields})
}
