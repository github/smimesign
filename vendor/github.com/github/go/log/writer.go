package log

import (
	"io"
	"os"
	"sync"
)

// SyncedWriter wraps an io.Writer in a thread-safe way
type SyncedWriter struct {
	Writer io.Writer
	sync.Mutex
}

// Write implements the io.Writer interface
func (s *SyncedWriter) Write(b []byte) (int, error) {
	s.Lock()
	n, err := s.Writer.Write(b)
	s.Unlock()
	return n, err
}

// Stdout is a thread-safe io.Writer that writes to Stdout
var Stdout = &SyncedWriter{Writer: os.Stdout}

// Stderr is a thread-safe io.Writer that writes to Stderr
var Stderr = &SyncedWriter{Writer: os.Stderr}
