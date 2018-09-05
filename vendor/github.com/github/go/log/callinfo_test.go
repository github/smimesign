package log

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testStruct struct {
}

func (s *testStruct) Test1(log *Logger) {
	log.Info("testing pointer receiver", CallInfo("X", "{Module}@{Function}"))
}

func (s testStruct) Test2(log *Logger) {
	log.Error("testing method receiver", CallInfo("X", "{Module}@{Function}"))

	f := func() {
		log.Debug("testing anonymous func", CallInfo("X", "{Module}@{Function}"))
	}
	f()
}

func assertCallInfo(t *testing.T, line, ns, st, fn, me, at, mod string) {
	assert.Contains(t, line, "ns="+ns)
	assert.Contains(t, line, "st="+st)
	assert.Contains(t, line, "fn="+fn)
	assert.Contains(t, line, "me="+me)
	assert.Contains(t, line, "at="+at)
	assert.Contains(t, line, "mod="+mod)
	assert.Contains(t, line, "X="+mod+"@"+fn)
}

func TestDebugInfo(t *testing.T) {
	buf := &bytes.Buffer{}
	log := New(DebugLevel, &Logfmt{Sink: &SyncedWriter{Writer: buf}}).With(
		CallInfo("ns", "{Namespace}"),
		CallInfo("st", "{Struct}"),
		CallInfo("fn", "{Function}"),
		CallInfo("me", "{Method}"),
		CallInfo("at", "{File}:{Line}"),
		CallInfo("mod", "{Module}"),
	)

	tst := testStruct{}
	tstp := &testStruct{}

	log.Info("testing the source", CallInfo("X", "{Module}@{Function}"))

	tst.Test1(log)
	tst.Test2(log)

	tstp.Test1(log)
	tstp.Test2(log)

	lines := getAllLines(buf)
	assertCallInfo(t, lines[0], "log", "", "TestDebugInfo", "", "callinfo_test.go:51", "log")

	assertCallInfo(t, lines[1], "testStruct", "testStruct", "Test1", "Test1", "callinfo_test.go:15", "log")
	assertCallInfo(t, lines[2], "testStruct", "testStruct", "Test2", "Test2", "callinfo_test.go:19", "log")
	assertCallInfo(t, lines[3], "testStruct", "testStruct", "func1", "Test2", "callinfo_test.go:22", "log")

	assertCallInfo(t, lines[4], "testStruct", "testStruct", "Test1", "Test1", "callinfo_test.go:15", "log")
	assertCallInfo(t, lines[5], "testStruct", "testStruct", "Test2", "Test2", "callinfo_test.go:19", "log")
	assert.Contains(t, lines[5], "X=log@Test2")
	assertCallInfo(t, lines[6], "testStruct", "testStruct", "func1", "Test2", "callinfo_test.go:22", "log")

	assert.Equal(t, 6, len(log.ctx))
}

func BenchmarkCallinfo(b *testing.B) {
	fmt := Logfmt{Sink: ioutil.Discard}
	logger := New(InfoLevel, &fmt)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.Info("call info", String("foobar", "baz"), CallInfo("at", "{Module}"))
		}
	})
}
