// Package ps provides a simple API to report the current process statistics to
// a statsd endpoint
package ps

import (
	"runtime"
	"time"

	"github.com/github/go/stats"
)

// Report starts reporting the current process' statistics to the given stats
// Client.  The reported metrics are sent every `interval`. They are all
// namespaced under "proc.*".
func Report(stats stats.Client, interval time.Duration) {
	go reporter(stats, interval)
}

func reporter(stats stats.Client, interval time.Duration) {
	var lastPauseNs uint64 = 0
	memStats := &runtime.MemStats{}

	for {
		runtime.ReadMemStats(memStats)

		stats.Gauge("proc.goroutines", int64(runtime.NumGoroutine()))
		stats.Gauge("proc.memory.allocated", int64(memStats.Alloc))
		stats.Gauge("proc.memory.mallocs", int64(memStats.Mallocs))
		stats.Gauge("proc.memory.frees", int64(memStats.Frees))
		stats.Gauge("proc.memory.gc.total_pause", int64(time.Duration(memStats.PauseTotalNs)/time.Millisecond))
		stats.Gauge("proc.memory.heap", int64(memStats.HeapAlloc))
		stats.Gauge("proc.memory.stack", int64(memStats.StackInuse))

		if lastPauseNs > 0 {
			pauseSinceLastSample := int64(memStats.PauseTotalNs - lastPauseNs)
			stats.Gauge("proc.memory.gc.pause_per_second",
				pauseSinceLastSample/int64(time.Millisecond)/int64(interval.Seconds()))
		}

		lastPauseNs = memStats.PauseTotalNs
		time.Sleep(interval)
	}
}
