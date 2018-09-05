package middleware

import (
	"net/http"
)

// Headers is a middleware that writes a default set of headers to every
// outgoing request, including a "Server" header, a "Date" header and
// any amount of user-configured headers.
type Headers struct {
	// ServerName will be written as the value for the "Server" header.
	ServerName string

	// Headers is a key-value map of user-supplied headers that will be
	// appended to all outgoing requests.
	Headers map[string]string
}

// ServeHTTP implements a Negroni-compatible `negroni.Middleware`
func (m *Headers) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	h := w.Header()
	for k, v := range m.Headers {
		h.Add(k, v)
	}

	h.Set("Server", m.ServerName)
	next(w, r)
}

// Handler allows manual chaining of this middleware
func (m *Headers) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.ServeHTTP(w, r, http.HandlerFunc(next.ServeHTTP))
	})
}
