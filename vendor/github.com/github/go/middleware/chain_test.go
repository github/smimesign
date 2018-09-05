package middleware

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A constructor for middleware
// that writes its own "tag" into the RW and does nothing else.
// Useful in checking if a chain is behaving in the right order.
func tagMiddleware(tag string) Constructor {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(tag))
			h.ServeHTTP(w, r)
		})
	}
}

var testApp = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("app\n"))
})

func TestThenWorksWithNoMiddleware(t *testing.T) {
	f := Chain{}.Then(testApp)
	assert.Equal(t,
		reflect.ValueOf(testApp).Pointer(),
		reflect.ValueOf(f).Pointer())
}

func TestThenTreatsNilAsDefaultServeMux(t *testing.T) {
	assert.Equal(t, Chain{}.Then(nil), http.DefaultServeMux)
}

func TestThenConstructsHandlerFunc(t *testing.T) {
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	chained := Chain{}.Then(fn)
	rec := httptest.NewRecorder()

	chained.ServeHTTP(rec, (*http.Request)(nil))
	assert.IsType(t, (http.HandlerFunc)(nil), chained)
}

func TestThenOrdersHandlersCorrectly(t *testing.T) {
	t1 := tagMiddleware("t1\n")
	t2 := tagMiddleware("t2\n")
	t3 := tagMiddleware("t3\n")

	chained := Chain{t1, t2, t3}.Then(testApp)

	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	chained.ServeHTTP(w, r)
	assert.Equal(t, "t1\nt2\nt3\napp\n", w.Body.String())
}

func TestAppendAddsHandlersCorrectly(t *testing.T) {
	chain := Chain{tagMiddleware("t1\n"), tagMiddleware("t2\n")}
	newChain := chain.Append(tagMiddleware("t3\n"), tagMiddleware("t4\n"))

	assert.Equal(t, 2, len(chain))
	assert.Equal(t, 4, len(newChain))

	chained := newChain.Then(testApp)

	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	chained.ServeHTTP(w, r)
	assert.Equal(t, "t1\nt2\nt3\nt4\napp\n", w.Body.String())
}

func TestAppendRespectsImmutability(t *testing.T) {
	chain := Chain{tagMiddleware("")}
	newChain := chain.Append(tagMiddleware(""))
	assert.NotEqual(t, &chain[0], &newChain[0])
}

func TestExtendAddsHandlersCorrectly(t *testing.T) {
	chain1 := Chain{tagMiddleware("t1\n"), tagMiddleware("t2\n")}
	chain2 := Chain{tagMiddleware("t3\n"), tagMiddleware("t4\n")}
	newChain := chain1.Extend(chain2)

	assert.Equal(t, 2, len(chain1))
	assert.Equal(t, 2, len(chain2))
	assert.Equal(t, 4, len(newChain))

	chained := newChain.Then(testApp)

	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	chained.ServeHTTP(w, r)
	assert.Equal(t, "t1\nt2\nt3\nt4\napp\n", w.Body.String())
}

func TestExtendRespectsImmutability(t *testing.T) {
	chain := Chain{tagMiddleware("")}
	newChain := chain.Extend(Chain{tagMiddleware("")})
	assert.NotEqual(t, &chain[0], &newChain[0])
}
