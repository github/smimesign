package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testHeaders = map[string]string{
	"X-Test-Suite": "true",
}

var fakeApp = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/panic" {
		panic("this is a panic, haha")
	}
	w.Write([]byte("Hello World\n"))
})

func testHandler(t *testing.T, h http.Handler) {
	if r, err := http.NewRequest("GET", "/", nil); err == nil {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "true", w.HeaderMap.Get("X-Test-Suite"))
		assert.Equal(t, "test", w.HeaderMap.Get("Server"))
	}

	if r, err := http.NewRequest("GET", "/panic", nil); err == nil {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(t, 500, w.Code)
		assert.Equal(t, "true", w.HeaderMap.Get("X-Test-Suite"))
		assert.Equal(t, "test", w.HeaderMap.Get("Server"))
		assert.Contains(t, w.Body.String(), "PANIC")
		t.Log(w.Body.String())
	}
}

func TestChainIntegration(t *testing.T) {
	a := &Recovery{Debug: true}
	b := &Headers{ServerName: "test", Headers: testHeaders}
	h := Chain{a.Handler, b.Handler}.Then(fakeApp)
	testHandler(t, h)
}

func TestManualChaining(t *testing.T) {
	a := &Recovery{Debug: true}
	b := &Headers{ServerName: "test", Headers: testHeaders}
	h := a.Handler(b.Handler(fakeApp))
	testHandler(t, h)
}
