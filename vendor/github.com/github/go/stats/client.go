// Package stats provides a statsd-compatible client for metrics reporting
package stats

import (
	"io"
	"net"
	"time"
)

// Type defines the different metric types that this client can report
type Type byte

const (
	Counter   Type = 'c'
	Gauge     Type = 'g'
	Histogram Type = 'h'
	Timing    Type = 'h'
	Event     Type = 'e'
	sentinel  Type = '0'
)

// Client is a generic interface for a Statsd-compatible metrics client.  It is
// defined this way to allow swapping the implementation of the underlying
// client.
type Client interface {
	Report(t Type, key string, value float64, tags Tags, rate float32)
	ReportEvent(title, text string, tags Tags)
	Gauge(key string, value int64)
	Counter(key string, value int64)
	Histogram(key string, value int64)
	Timing(key string, value time.Duration)
	Event(title, text string)

	Start()
	Stop()
}

// DataDog returns a Sink that writes to the default DataDog agent running in
// localhost.
func DataDog() io.Writer {
	return UDP("127.0.0.1:28125")
}

// UDP returns a Sink that writes to the given Statsd server using the UDP
// protocol
func UDP(addr string) io.Writer {
	udp, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	fd, err := net.DialUDP("udp", nil, udp)
	if err != nil {
		panic(err)
	}
	return fd
}

// TimeMs runs the given block of code in func and reports its duration to the
// Statsd client. It also returns the reported duration.
func TimeMs(st Client, key string, run func()) float64 {
	now := time.Now()
	run()
	end := time.Since(now)
	st.Timing(key, end)
	return float64(end) / float64(time.Millisecond)
}

// Null is the "empty" Statsd client. Since it fulfills the Client interface, it
// can be used to disable metrics reporting e.g. when running an application in
// CI.
type Null struct{}

func (n *Null) Start()                                                            {}
func (n *Null) Stop()                                                             {}
func (n *Null) Report(t Type, key string, value float64, tags Tags, rate float32) {}
func (n *Null) ReportEvent(title, text string, tags Tags)                         {}
func (n *Null) Gauge(key string, value int64)                                     {}
func (n *Null) Counter(key string, value int64)                                   {}
func (n *Null) Histogram(key string, value int64)                                 {}
func (n *Null) Timing(key string, value time.Duration)                            {}
func (n *Null) Event(title, text string)                                          {}
