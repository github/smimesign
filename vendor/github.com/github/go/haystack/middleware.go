package haystack

import (
	"net/http"

	"github.com/github/go/errors"
)

type haystackWrapper struct {
	reporter *Reporter
	next     http.HandlerFunc
}

// ServeHTTP implements the http.Handler interface for a haystack wrapper
// allowing one to be used as middleware to collect and log panics
func (wrapper haystackWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			wrapper.reporter.ReportBlocking(errors.Panic(err), map[string]string{
				"method": r.Method,
				"url":    r.URL.String(),
			})

			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}()

	wrapper.next(w, r)
}

func (reporter *Reporter) Middleware(next http.Handler) http.Handler {
	return haystackWrapper{reporter, next.ServeHTTP}
}

func (reporter *Reporter) MiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	return haystackWrapper{reporter, next}.ServeHTTP
}
