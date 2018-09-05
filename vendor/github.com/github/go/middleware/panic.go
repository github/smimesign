package middleware

import (
	"fmt"
	"net/http"

	"github.com/github/go/errors"
)

// Recovery is a middleware that handles panics during the normal request
// lifecycle and returns a 500 error code if possible. An optional callback is
// provided to report the panic
type Recovery struct {
	// Debug marks whether the full stack trace of the panic should be printed
	// as part of the request body.
	Debug bool

	// Report is a callback that will receive the rescued panic, wrapped as an
	// error. It should ideally return right away.
	Report func(err error)
}

// ServeHTTP implements a Negroni-compatible `negroni.Middleware`
func (rec *Recovery) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	defer func() {
		if err := recover(); err != nil {
			wrap := errors.Panic(err)

			if rw.Header().Get("Content-Type") == "" {
				rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			}

			rw.WriteHeader(http.StatusInternalServerError)

			if rec.Debug {
				fmt.Fprintf(rw, "PANIC: %+v", wrap)
			}

			if rec.Report != nil {
				rec.Report(wrap)
			}
		}
	}()

	next(rw, r)
}

// Handler allows manual chaining of this middleware
func (rec *Recovery) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.ServeHTTP(w, r, http.HandlerFunc(next.ServeHTTP))
	})
}
