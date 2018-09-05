package monitor

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"
)

// The Goroutines monitor checks periodically for unbounded Goroutine growth
// and reports it to a given user callback. It can also optionally dump the
// current goroutine stacks to a file on disk.
type Goroutines struct {
	// MaxGoroutines is the maximum number of goroutines after which the
	// monitor will consider a "critical" condition and report it as such.
	// Defaults to 5000.
	MaxGoroutines int

	// Interval is the frequency at which the current goroutine count will be
	// checked. Defaults to 10 seconds.
	Interval time.Duration

	// DumpPath is the path on disk where stack traces for all running
	// goroutines will be dumped when reaching a "critical" situation.  It must
	// be a path to an existing folder. Stack dumps will follow the following
	// pattern:
	//
	//  DumpPath/stacks.$PID.$TIME
	//
	// If empty, stack dumps will not be written to disk
	DumpPath string

	// Signal is the OS signal that will cause the monitor to write a stack
	// dump. If empty, the monitor will not listen for any signals.
	Signal os.Signal

	// Event is a callback that will be issued whenever the goroutine situation
	// changes. Possible values for `ev` are:
	//
	// - "critical": when the current goroutine count crosses the MaxGoroutines
	// threshold
	//
	// - "healthy": when the current goroutine count recovers from being
	// critical
	//
	// - "stackdump": when a stack dump is being written because of an user
	// signal
	//
	// `count` is always the current number of goroutines. If Event is empty,
	// events will be discarded.
	Event func(ev string, count int)
}

// Run starts the Goroutine monitor
func (m *Goroutines) Run() {
	if m.MaxGoroutines == 0 {
		m.MaxGoroutines = 5000
	}
	if m.Interval == 0 {
		m.Interval = 10 * time.Second
	}
	if m.Event == nil {
		// Swallow events
		m.Event = func(_ string, _ int) {}
	}

	go m.run()
}

// StackDump forces the monitor to write out a stack dump file to disk
// It has no effect if the DumpPath field is not set
func (m *Goroutines) StackDump() {
	if m.DumpPath == "" {
		return
	}

	now := time.Now().Format(time.RFC3339)
	filename := fmt.Sprintf("stacks.%d.%s", os.Getpid(), now)

	if f, err := os.Create(path.Join(m.DumpPath, filename)); err == nil {
		pprof.Lookup("goroutine").WriteTo(f, 1)
		f.Close()
	}
}

func (m *Goroutines) run() {
	healthy := true
	tick := time.NewTicker(m.Interval)

	sig := make(chan os.Signal, 1)
	if m.Signal != syscall.Signal(0) {
		signal.Notify(sig, m.Signal)
	}

	for {
		select {
		case <-sig:
			m.Event("stackdump", 0)
			m.StackDump()
		case <-tick.C:
			goroutines := runtime.NumGoroutine()
			if goroutines > m.MaxGoroutines {
				if !healthy {
					continue
				}
				m.Event("critical", goroutines)
				m.StackDump()
				healthy = false
			} else {
				if !healthy {
					m.Event("healthy", goroutines)
				}
				healthy = true
			}
		}
	}
}
