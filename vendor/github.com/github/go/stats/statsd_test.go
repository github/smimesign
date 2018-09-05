package stats

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func BenchmarkStatsdMetric(b *testing.B) {
	tags := TagSet{"host": "statsd.iad.github.net", "benchmark": ""}.Tags()
	std := Statsd{
		Sink:   ioutil.Discard,
		Prefix: "benchmark",
	}
	std.Start()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			std.Report(Histogram, "a.metric.name", 123456789.500012345, tags, 1.0)
		}
	})

	std.Stop()
}

func BenchmarkStatsdEvent(b *testing.B) {
	tags := TagSet{"host": "statsd.iad.github.net", "benchmark": ""}.Tags()
	std := Statsd{
		Sink:   ioutil.Discard,
		Prefix: "benchmark",
	}
	std.Start()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			std.ReportEvent("test", "a.metric.name", tags)
		}
	})

	std.Stop()
}

type DebugBuffer struct {
	b bytes.Buffer
	m sync.Mutex
}

func (b *DebugBuffer) Write(p []byte) (n int, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.Write(p)
}

func TestSimpleMetricReporting(t *testing.T) {
	count := 100
	buf := &DebugBuffer{}
	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
	}
	std.Start()

	for i := 0; i < count; i++ {
		std.Report(Counter, "a.metric.name", float64(i), nil, 1.0)
	}

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, count, len(metrics))

	for i, m := range metrics {
		parts := strings.Split(m, "|")
		assert.Equal(t, 2, len(parts))
		assert.Equal(t, fmt.Sprintf("testing.a.metric.name:%d", i), parts[0])
		assert.Equal(t, "c", parts[1])
	}
}

func TestSimpleTimingReporting(t *testing.T) {
	buf := &DebugBuffer{}
	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
	}
	std.Start()

	tim := time.Millisecond * 700

	std.Timing("a.time0", tim)

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, 1, len(metrics))

	assert.Equal(t, "testing.a.time0:700|h", metrics[0])
}

func TestSimpleTimingFractionalReporting(t *testing.T) {
	buf := &DebugBuffer{}
	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
	}
	std.Start()

	tim := time.Millisecond*700 + time.Microsecond*225

	std.Timing("a.time", tim)

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, 1, len(metrics))

	assert.Equal(t, "testing.a.time:700.225|h", metrics[0])
}

func TestSimpleEventReporting(t *testing.T) {
	count := 100
	buf := &DebugBuffer{}
	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
	}
	std.Start()

	for i := 0; i < count; i++ {
		std.ReportEvent("test", fmt.Sprintf("test%d", i), nil)
	}

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, count, len(metrics))

	for i, m := range metrics {
		parts := strings.Split(m, ":")
		assert.Equal(t, 2, len(parts))
		assert.Equal(t, fmt.Sprintf("_e{4,%d}", len(fmt.Sprintf("test%d", i))), parts[0])
		assert.Equal(t, fmt.Sprintf("test|test%d", i), parts[1])
	}
}

func TestSampling(t *testing.T) {
	count := 1000
	buf := &DebugBuffer{}
	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
	}
	std.Start()

	for i := 0; i < count; i++ {
		std.Report(Counter, "a.metric.name", float64(i), nil, 0.25)
	}

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.InDelta(t, count/4, len(metrics), 25)

	for _, m := range metrics {
		parts := strings.Split(m, "|")
		assert.Equal(t, 3, len(parts))
		assert.Equal(t, "@0.25", parts[2])
	}
}

func TestTags(t *testing.T) {
	count := 100
	buf := &DebugBuffer{}

	tagsA := TagSet{"a_tag": "testing", "foobar": ""}.Tags()
	tagsB := TagSet{"b_tag": "testing", "bazinga": ""}.Tags()

	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
		Tags:   tagsA,
	}
	std.Start()

	for i := 0; i < count; i++ {
		if i%2 == 0 {
			std.Report(Counter, "a.tagged.metric", float64(i), tagsB, 1.0)
		} else {
			std.Report(Counter, "non.tagged.metric", float64(i), nil, 1.0)
		}
	}

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, count, len(metrics))

	expectedA := "#" + string(tagsA[:len(tagsA)-1])
	expectedB := "#" + string(tagsA) + string(tagsB[:len(tagsB)-1])

	for i, m := range metrics {
		parts := strings.Split(m, "|")
		assert.Equal(t, 3, len(parts))

		if i%2 == 0 {
			assert.Equal(t, expectedB, parts[2])
		} else {
			assert.Equal(t, expectedA, parts[2])
		}
	}
}

func TestParallelReporting(t *testing.T) {
	count := 1000
	goroutines := 4

	buf := &DebugBuffer{}
	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
	}
	std.Start()

	var wg sync.WaitGroup
	for n := 0; n < goroutines; n++ {
		wg.Add(1)
		go func() {
			for i := 0; i < count; i++ {
				std.Report(Counter, "a.metric.name", float64(i), nil, 1.0)
			}
			wg.Done()
		}()
	}

	wg.Wait()
	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, count*goroutines, len(metrics))

	for _, m := range metrics {
		parts := strings.Split(m, "|")
		assert.Equal(t, 2, len(parts))
		assert.Equal(t, "c", parts[1])
	}
}

func TestNoPanicOnStoppedClientSend(t *testing.T) {
	buf := &DebugBuffer{}
	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
	}
	std.Start()
	std.Stop()

	std.Report(Counter, "a.metric.name", 42.0, nil, 1.0)
}

func TestClientRestartable(t *testing.T) {
	count := 100
	buf := &DebugBuffer{}
	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
	}
	std.Start()
	std.Stop()
	std.Start()

	for i := 0; i < count; i += 1 {
		std.Report(Counter, "a.metric.name", float64(i), nil, 1.0)
	}

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, count, len(metrics))

	for i, m := range metrics {
		parts := strings.Split(m, "|")
		assert.Equal(t, 2, len(parts))
		assert.Equal(t, fmt.Sprintf("testing.a.metric.name:%d", i), parts[0])
		assert.Equal(t, "c", parts[1])
	}
}

func BenchmarkSubclientMetricNoTags(b *testing.B) {
	tags := TagSet{"host": "statsd.iad.github.net", "benchmark": ""}.Tags()
	std := Statsd{
		Sink:   ioutil.Discard,
		Prefix: "benchmark",
	}
	std.Start()

	sc := std.WithPrefix(std.Prefix + ".scnotags")

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sc.Report(Histogram, "a.metric.name", 123456789.500012345, tags, 1.0)
		}
	})

	std.Stop()
}

func BenchmarkSubclientMetricTagged(b *testing.B) {
	tags := TagSet{"host": "statsd.iad.github.net", "benchmark": ""}.Tags()
	std := Statsd{
		Sink:   ioutil.Discard,
		Prefix: "benchmark",
	}
	std.Start()

	sc := std.WithPrefix(std.Prefix + ".sctagged")
	sc.Tags = TagSet{"some": "stuff", "more": "stuff"}.Tags()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sc.Report(Histogram, "a.metric.name", 123456789.500012345, tags, 1.0)
		}
	})

	std.Stop()
}

func BenchmarkSubclientEventNoTags(b *testing.B) {
	tags := TagSet{"host": "statsd.iad.github.net", "benchmark": ""}.Tags()
	std := Statsd{
		Sink:   ioutil.Discard,
		Prefix: "benchmark",
	}
	std.Start()

	sc := std.WithPrefix(std.Prefix + ".scnotags")

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sc.ReportEvent("test", "a.metric.name", tags)
		}
	})

	std.Stop()
}

func BenchmarkSubclientEventTagged(b *testing.B) {
	tags := TagSet{"host": "statsd.iad.github.net", "benchmark": ""}.Tags()
	std := Statsd{
		Sink:   ioutil.Discard,
		Prefix: "benchmark",
	}
	std.Start()

	sc := std.WithPrefix(std.Prefix + ".sctagged")
	sc.Tags = TagSet{"some": "stuff", "more": "stuff"}.Tags()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sc.ReportEvent("test", "a.metric.name", tags)
		}
	})

	std.Stop()
}

func TestSimpleMetricSubclient(t *testing.T) {
	count := 100
	buf := &DebugBuffer{}
	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
	}
	std.Start()

	sc := std.WithPrefix(std.Prefix + "subclient")

	for i := 0; i < count; i++ {
		sc.Report(Counter, "a.metric.name", float64(i), nil, 1.0)
	}

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, count, len(metrics))

	for i, m := range metrics {
		parts := strings.Split(m, "|")
		assert.Equal(t, 2, len(parts))
		assert.Equal(t, fmt.Sprintf("testing.subclient.a.metric.name:%d", i), parts[0])
		assert.Equal(t, "c", parts[1])
	}
}

func TestSimpleEventSubclient(t *testing.T) {
	count := 100
	buf := &DebugBuffer{}
	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
	}
	std.Start()

	sc := std.WithPrefix(std.Prefix + "subclient")

	for i := 0; i < count; i++ {
		sc.ReportEvent("test", fmt.Sprintf("test%d", i), nil)
	}

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, count, len(metrics))

	for i, m := range metrics {
		parts := strings.Split(m, ":")
		assert.Equal(t, 2, len(parts))
		assert.Equal(t, fmt.Sprintf("_e{4,%d}", len(fmt.Sprintf("test%d", i))), parts[0])
		assert.Equal(t, fmt.Sprintf("test|test%d", i), parts[1])
	}
}

func TestTagsSubclient(t *testing.T) {
	count := 100
	buf := &DebugBuffer{}

	tagsA := TagSet{"a_tag": "testing", "foobar": ""}.Tags()
	tagsB := TagSet{"b_tag": "testing", "bazinga": ""}.Tags()

	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
		Tags:   tagsA,
	}
	std.Start()

	sc := std.WithPrefix(std.Prefix + "sc")

	for i := 0; i < count; i++ {
		if i%2 == 0 {
			sc.Report(Counter, "a.tagged.metric", float64(i), tagsB, 1.0)
		} else {
			sc.Report(Counter, "non.tagged.metric", float64(i), nil, 1.0)
		}
	}

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, count, len(metrics))

	expectedA := "#" + string(tagsA[:len(tagsA)-1])
	expectedB := "#" + string(tagsA) + string(tagsB[:len(tagsB)-1])

	for i, m := range metrics {
		parts := strings.Split(m, "|")
		assert.Equal(t, 3, len(parts))

		if i%2 == 0 {
			assert.Equal(t, expectedB, parts[2])
		} else {
			assert.Equal(t, expectedA, parts[2])
		}
	}
}

func TestTagsSubclientTagged(t *testing.T) {
	count := 100
	buf := &DebugBuffer{}

	tagsA := TagSet{"a_tag": "testing", "foobar": ""}.Tags()
	tagsB := TagSet{"b_tag": "testing", "bazinga": ""}.Tags()
	tagsC := TagSet{"c_tag": "moar", "quux": "eck"}.Tags()

	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
		Tags:   tagsA,
	}
	std.Start()

	sc := std.WithPrefix(std.Prefix + "sc")
	sc.Tags = append(sc.Tags, tagsC...)

	for i := 0; i < count; i++ {
		if i%2 == 0 {
			sc.Report(Counter, "a.tagged.metric", float64(i), tagsB, 1.0)
		} else {
			sc.Report(Counter, "non.tagged.metric", float64(i), nil, 1.0)
		}
	}

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, count, len(metrics))

	expectedA := "#" + string(tagsA) + string(tagsC[:len(tagsC)-1])
	expectedB := "#" + string(tagsA) + string(tagsC) + string(tagsB[:len(tagsB)-1])

	for i, m := range metrics {
		parts := strings.Split(m, "|")
		assert.Equal(t, 3, len(parts))

		if i%2 == 0 {
			assert.Equal(t, expectedB, parts[2])
		} else {
			assert.Equal(t, expectedA, parts[2])
		}
	}
}

func TestWithTagsSubClient(t *testing.T) {
	count := 100
	buf := &DebugBuffer{}

	tagsA := TagSet{"a_tag": "testing", "foobar": ""}.Tags()
	tagsB := TagSet{"b_tag": "testing", "bazinga": ""}.Tags()
	tagsC := TagSet{"c_tag": "moar", "quux": "eck"}.Tags()

	std := Statsd{
		Sink:   buf,
		Prefix: "testing",
		Tags:   tagsA,
	}
	std.Start()

	sc := std.WithTags(tagsB)

	for i := 0; i < count; i++ {
		if i%2 == 0 {
			sc.Report(Counter, "a.tagged.metric", float64(i), tagsC, 1.0)
		} else {
			sc.Report(Counter, "non.tagged.metric", float64(i), nil, 1.0)
		}
	}

	std.Stop()

	metrics := strings.Split(buf.b.String(), "\n")
	metrics = metrics[:len(metrics)-1]

	assert.Equal(t, count, len(metrics))

	expectedA := "#" + string(tagsB[:len(tagsB)-1])
	expectedB := "#" + string(tagsB) + string(tagsC[:len(tagsC)-1])

	for i, m := range metrics {
		parts := strings.Split(m, "|")
		assert.Equal(t, 3, len(parts))

		if i%2 == 0 {
			assert.Equal(t, expectedB, parts[2])
		} else {
			assert.Equal(t, expectedA, parts[2])
		}
	}
}
