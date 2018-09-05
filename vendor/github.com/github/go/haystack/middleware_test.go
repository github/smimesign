package haystack

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func panicHandler(_ http.ResponseWriter, _ *http.Request) {
	panic("Don't panic, Captain Mainwaring!")
}

type fakeHaystackPoster struct {
	Needle map[string]interface{}
	Err    error
	Count  int
}

func (w *fakeHaystackPoster) Post(_ string, _ string, body io.Reader) (res *http.Response, err error) {
	buf, err := ioutil.ReadAll(body)
	w.Err = err
	json.Unmarshal(buf, &w.Needle)
	w.Count += 1
	return nil, nil
}

func TestHaystackAsMiddleware(t *testing.T) {
	haystack := fakeHaystackPoster{}
	reporter := Reporter{Client: &haystack}

	request := httptest.NewRequest("GET", "http://example.invalid/foo", nil)
	response := httptest.NewRecorder()
	stack := reporter.Middleware(http.HandlerFunc(panicHandler))

	stack.ServeHTTP(response, request)

	assert.Equal(t, response.Code, 500)

	assert.NoError(t, haystack.Err)
	assert.Equal(t, 1, haystack.Count)
	assert.Contains(t, haystack.Needle, "backtrace")
	assert.Equal(t, "GET", haystack.Needle["method"])
	assert.Equal(t, "http://example.invalid/foo", haystack.Needle["url"])
}

func TestHaystackAsMiddlewareFunc(t *testing.T) {
	haystack := fakeHaystackPoster{}
	reporter := Reporter{Client: &haystack}

	request := httptest.NewRequest("GET", "http://example.invalid/foo", nil)
	response := httptest.NewRecorder()
	stack := reporter.MiddlewareFunc(panicHandler)

	stack(response, request)

	assert.Equal(t, response.Code, 500)

	assert.NoError(t, haystack.Err)
	assert.Equal(t, 1, haystack.Count)
	assert.Contains(t, haystack.Needle, "backtrace")
	assert.Equal(t, "GET", haystack.Needle["method"])
	assert.Equal(t, "http://example.invalid/foo", haystack.Needle["url"])
}
