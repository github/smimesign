package middleware

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/github/go/stats"
)

// RequestLogger is an interface for a logger than can process http.Request
// objects. It can be used to log individual requests from the middleware.
type RequestLogger interface {
	LogRequest(r *http.Request, duration float64)
}

// Stats is a middleware that submits statistics about all incoming requests.
// It will measure the duration of each request, and the active number of
// requests at any given time, and it will report those to the given
// stats.Client
type Stats struct {
	// Stats is an object that implements the stats.Client interface. Metrics
	// will be reported to it
	Stats stats.Client

	// Logger is an object that implements the RequestLogger interface. If
	// present, each individual request will be submitted for logging.
	Logger RequestLogger

	// CurrentConnections is the number of currently active HTTP requests (i.e.
	// the requests being served)
	CurrentConnections int64
}

// ReportCurrentConnections will enable a goroutine to periodically submit the
// number of active connections to the stats Client.
func (m *Stats) ReportCurrentConnections(interval time.Duration) {
	go func() {
		for {
			m.Stats.Gauge("active_conns", atomic.LoadInt64(&m.CurrentConnections))
			time.Sleep(interval)
		}
	}()
}

// ServeHTTP implements a Negroni-compatible `negroni.Middleware`
func (m *Stats) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	atomic.AddInt64(&m.CurrentConnections, 1)
	t := stats.TimeMs(m.Stats, "response_time", func() { next(rw, r) })
	atomic.AddInt64(&m.CurrentConnections, -1)

	if m.Logger != nil {
		m.Logger.LogRequest(r, t)
	}
}

// Handler allows manual chaining of this middleware
func (m *Stats) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.ServeHTTP(w, r, http.HandlerFunc(next.ServeHTTP))
	})
}
