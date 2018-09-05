package stats

import (
	"io"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

type metric struct {
	prefix   string
	name     string
	text     string
	value    float64
	rate     float32
	char     Type
	tags     Tags
	conftags Tags
}

// Statsd is the implementation of a Statsd-compatible metrics client. This
// client also supports the following extensions:
//
// - Buffered metrics: by default all metrics are stored in a buffer and
// flushed to the sink after an interval
//
// - Downsampled metrics: metrics can be reported at a given rate
//
// - Tags: metrics can be reportd with user-supplied tags attached (this is a
// DataDog feature which may not be supported by all statsd server
// implementations)
//
// Users must make sure to call Statsd.Start() after initializing the Statsd
// client. All methods on the client are safe for multi-threaded usage.
type Statsd struct {
	// A Sink is the endpoint where metrics will be periodically written to.
	// It should usually be an UDP socket pointing to the StatsD server, but
	// any other struct implementing io.Writer will also work.
	Sink io.Writer

	// Interval is the duration between flushes to the Sink. The metrics buffer
	// will be periodically flushed every time it reaches its maximum capacity
	// or every Interval, even if the buffer is not yet full.
	Interval time.Duration

	// Prefix will be appended before the name of all outgoing metrics. If the
	// Prefix does not end with a period `.`, one will be appended automatically.
	Prefix string

	// Tags is the default set of user-defined tags that will be sent with each
	// reported metric. In addition to these tags, each individual report can also
	// define its own tags to add (on top of the default ones).
	Tags Tags

	metrics  chan<- metric
	done     <-chan struct{}
	initOnce sync.Once
}

const maxWriteSize = 1450
const maxWriteDelay = 500 * time.Millisecond

// TagSet is a dictionary of tags (key-value pairs). The values can be empty
// for tags that are "unary".
//
// A TagSet must be converted into a Tags type to be used when reporting
// metrics. This conversion is performed by the TagSet.Tags() method, and
// should ideally be cached for performance.
type TagSet map[string]string

// Tags is the serialized form of the tags attached to a specific metric.
// It can be generated from a TagSet.
type Tags []byte

// Tags generates a serialized Tags struct from a TagSet. The result
// of this serialization should be cached if possible.
func (t TagSet) Tags() Tags {
	var b Tags
	for k, v := range t {
		b = append(b, k...)
		if v != "" {
			b = append(b, ':')
			b = append(b, v...)
		}
		b = append(b, ',')
	}
	return b
}

func (m metric) serialize(buf []byte) []byte {
	if m.char == Event {
		return m.serializeAsEvent(buf)
	}
	return m.serializeAsMetric(buf)
}

func (m metric) byteLength() int {
	if m.char == Event {
		return m.byteLengthAsEvent()
	}
	return m.byteLengthAsMetric()
}

func (m metric) serializeAsMetric(buf []byte) []byte {
	buf = append(buf, m.prefix...)
	buf = append(buf, m.name...)
	buf = append(buf, ':')
	buf = strconv.AppendFloat(buf, m.value, 'g', 16, 64)
	buf = append(buf, []byte{'|', byte(m.char)}...)

	if m.rate < 1.0 {
		buf = append(buf, []byte{'|', '@'}...)
		buf = strconv.AppendFloat(buf, float64(m.rate), 'g', 4, 32)
	}

	if len(m.conftags) != 0 || len(m.tags) != 0 {
		buf = append(buf, []byte{'|', '#'}...)
		buf = append(buf, m.conftags...)
		buf = append(buf, m.tags...)
		buf = buf[:len(buf)-1]
	}

	return append(buf, byte('\n'))
}

func (m metric) byteLengthAsMetric() int {
	n := len(m.prefix) + len(m.name) + 17 + 4 + len(m.tags) + len(m.conftags)
	if m.rate < 1.0 {
		n += 7
	}
	return n
}

func (m metric) serializeAsEvent(buf []byte) []byte {
	buf = append(buf, "_e{"...)
	buf = strconv.AppendInt(buf, int64(len(m.name)), 10)
	buf = append(buf, ',')
	buf = strconv.AppendInt(buf, int64(len(m.text)), 10)
	buf = append(buf, "}:"...)
	buf = append(buf, m.name...)
	buf = append(buf, '|')
	buf = append(buf, m.text...)

	if len(m.conftags) != 0 || len(m.tags) != 0 {
		buf = append(buf, []byte{'|', '#'}...)
		buf = append(buf, m.conftags...)
		buf = append(buf, m.tags...)
		buf = buf[:len(buf)-1]
	}

	return append(buf, byte('\n'))
}

func (m metric) byteLengthAsEvent() int {
	return len(m.name) + len(m.text) + 23 + 4 + len(m.tags) + len(m.conftags)
}

func flush(sink io.Writer, buf []byte) []byte {
	if len(buf) > 0 {
		sink.Write(buf)
		buf = buf[:0]
	}
	return buf
}

func writeMetric(sink io.Writer, buf []byte, m *metric) []byte {
	expectedLen := m.byteLength()

	if len(buf)+expectedLen > cap(buf) {
		buf = flush(sink, buf)
	}

	if expectedLen > cap(buf) {
		sink.Write(m.serialize(nil))
		return buf
	}

	return m.serialize(buf)
}

// statsPump receives metrics from the metrics channel and either writes them
// out to the Sink or ignores them. The behavior is toggled by sending the sentinel
// metric over the metrics channel.
func statsPump(metrics <-chan metric, done chan<- struct{}, sink io.Writer, interval time.Duration) {
	buf := make([]byte, 0, maxWriteSize)
	ignoreMetrics := true
	ticks := time.NewTicker(interval)
	for {
		select {
		case m := <-metrics:
			if m.char == sentinel {
				if !ignoreMetrics {
					buf = flush(sink, buf)
				}

				ignoreMetrics = !ignoreMetrics
				done <- struct{}{}
				continue
			}

			if !ignoreMetrics {
				buf = writeMetric(sink, buf, &m)
			}
		case <-ticks.C:
			buf = flush(sink, buf)
		}
	}
}

// toggleStatsPump toggles whether the statsPump is sending out metrics or
// ignoring them.
func (st *Statsd) toggleStatsPump() {
	if st.done != nil {
		st.metrics <- metric{char: sentinel}
		<-st.done
	}
}

// regularizePrefix ensures that the Prefix ends with a '.', so that it
// can be contatenated with a metric name to form a valid metric path.
func (st *Statsd) regularizePrefix() {
	if st.Prefix != "" && !strings.HasSuffix(st.Prefix, ".") {
		st.Prefix = st.Prefix + "."
	}
}

// Start sets up the Statsd client and runs the goroutine that will take care
// of asynchrounously reporting the metrics to the Sink. This function must be
// called before attempting to report any metrics.
func (st *Statsd) Start() {
	st.initOnce.Do(func() {
		st.regularizePrefix()

		if st.Interval == time.Duration(0) {
			st.Interval = maxWriteDelay
		}

		metrics := make(chan metric, 8)
		done := make(chan struct{})

		st.metrics = metrics
		st.done = done

		go statsPump(metrics, done, st.Sink, st.Interval)
	})

	st.toggleStatsPump()
}

// Stop shuts down cleanly the Statsd client, making sure that all remaining
// buffered metrics are flushed. Metrics reported after Stop is called will be
// ignored.
func (st *Statsd) Stop() {
	st.toggleStatsPump()
}

// WithPrefix creates a new Statsd client associated with an existing one,
// so that metrics with different prefixes may be generated over one stream
// The Tags associated with the new client are copied from the existing one
// but can be overridden as desired.
func (st *Statsd) WithPrefix(prefix string) Statsd {
	if st.metrics == nil {
		// Donor client not yet started, so we start it now
		// otherwise channels will not be shared correctly
		st.Start()
	}

	newClient := *st
	newClient.done = nil
	newClient.Prefix = prefix
	newClient.regularizePrefix()
	return newClient
}

// WithTags creates a new Statsd client associated with an existing one,
// so that metrics with different tags may be generated over one stream
func (st *Statsd) WithTags(tags Tags) Statsd {
	if st.metrics == nil {
		// Donor client not yet started, so we start it now
		// otherwise channels will not be shared correctly
		st.Start()
	}

	newClient := *st
	newClient.done = nil
	newClient.Tags = tags
	return newClient
}

// Report sends an individual metric to the backend with type `t` and the given
// name/key and value. If tags is not nil, the given tags will be attached to the
// metric. If rate is less than 1, the metric will be downsampled accordingly and
// may or may not be sent.
//
// The helper functions Gauge, Counter, etc make reporting values simpler, but they
// do not support adding custom tags or a sample rate.
//
// This function does not block or allocate any memory. It should be safe to use
// on tight loops.
func (st *Statsd) Report(t Type, key string, value float64, tags Tags, rate float32) {
	if rate < 1.0 && rand.Float32() > rate {
		return
	}

	st.metrics <- metric{prefix: st.Prefix, name: key, value: value, char: t, rate: rate, tags: tags, conftags: st.Tags}
}

// ReportEvent sends an individual event to the backend. If tags is not nil, the
// given tags will be attached to the event.
//
// The helper function Event makes reporting events simpler, but does not
// support adding custom tags.
//
// This function does not block or allocate any memory. It should be safe to use
// on tight loops.
func (st *Statsd) ReportEvent(title, text string, tags Tags) {
	st.metrics <- metric{prefix: st.Prefix, char: Event, name: title, text: text, tags: tags, conftags: st.Tags}
}

// Gauge reports an individual Gauge metric. See `Report`.
func (st *Statsd) Gauge(key string, value int64) {
	st.Report(Gauge, key, float64(value), nil, 1.0)
}

// Counter reports an individual Counter metric. See `Report`.
func (st *Statsd) Counter(key string, value int64) {
	st.Report(Counter, key, float64(value), nil, 1.0)
}

// Histogram reports an individual Histogram metric. See `Report`.
func (st *Statsd) Histogram(key string, value int64) {
	st.Report(Histogram, key, float64(value), nil, 1.0)
}

// Timing reports an individual Timing metric in milliseconds. See `Report`.
func (st *Statsd) Timing(key string, value time.Duration) {
	st.Report(Timing, key, float64(value)/float64(time.Millisecond), nil, 1.0)
}

// Event reports an individual event. See `ReportEvent`.
func (st *Statsd) Event(title, text string) {
	st.ReportEvent(title, text, nil)
}
