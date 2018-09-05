// Package haystack provides a haystack reporter using either blocking or
// non-blocking calls. By default, the package uses its own HTTP client with a 5
// second time out, but any client can be set.
//
// Report and ReportBlocking send the errors to haystack.
//
//     ctx := map[string]string{"fn": "MyFunc"}
//
//     haystack.Report(err, ctx)
//
//     herr := haystack.ReportBlocking(err, ctx)
//     ...
//
// For control over the underlying client, create a Reporter:
//     client := &http.Client{}
//
//     reporter := &haystack.Reporter{Client: client}
//
//     reporter.Report(err, ctx)
package haystack

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/github/go/errors"
)

type stackTracer interface {
	StackTrace() errors.StackTrace
}

var defaultHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
}

type writerClient struct {
	out io.Writer
}

func (w *writerClient) Post(_ string, _ string, body io.Reader) (res *http.Response, err error) {
	var op bytes.Buffer
	var ip bytes.Buffer
	ip.ReadFrom(body)
	json.Indent(&op, ip.Bytes(), "Needle:", "\t")
	op.WriteTo(w.out)
	return nil, nil
}

var defaultWriterClient = &writerClient{out: os.Stdout}

type needle struct {
	err error
	ctx map[string]string
}

// Poster is the interface that the underlying client must support, to post needles.
type Poster interface {
	Post(url string, contentType string, body io.Reader) (res *http.Response, err error)
}

// Reporter is a Haystack client that can submit Golang errors as Needles.
type Reporter struct {
	// Client is the HTTP Client used to push needles to Haystack. If nil, a
	// default client with a 5s timeout will be used.
	Client Poster

	// URL is the Haystack endpoint where to POST the needles. The URL must
	// contain username & password if required for authentication.
	URL string

	// Hostname is the name of this machine. It will be reported as "host" on
	// all Needle payloads.
	Hostname string

	// App is the name of this application. It will be reported on all Needle
	// payloads.
	App string

	// MaxQueuedNeedles is the size of the channel where async needles are
	// stored.  Once this channel becomes full (i.e. because Haystack is not
	// responding), Report will silently drop new needles from reporting.
	MaxQueuedNeedles int

	needles chan needle
	once    sync.Once

	done chan struct{}
}

// DefaultReporter is the default reporter and is used by Report and ReportBlocking.
var DefaultReporter = Reporter{}

func init() {
	hostname, _ := os.Hostname()
	DefaultReporter.Hostname = hostname
}

// Close shuts down the reporter. Calling Report after Close will panic.
func (r *Reporter) Close() {
	if r.needles != nil {
		close(r.needles)
	}
	if r.done != nil {
		<-r.done
	}
}

// Report submits the given needle to the async reporting queue, and returns
// immediately. Errors when submitting the needle will be silently ignored.  If
// the needles queue is full, the needle will also be silently dropped. It is
// recommended to use this API as to not block the request thread whenever
// Haystack is down.
//
// See: ReportBlocking
func Report(err error, context map[string]string) {
	DefaultReporter.Report(err, context)
}

// Report submits the given needle to the async reporting queue, and returns
// immediately. Errors when submitting the needle will be silently ignored.  If
// the needles queue is full, the needle will also be silently dropped. It is
// recommended to use this API as to not block the request thread whenever
// Haystack is down.
//
// See: ReportBlocking
func (r *Reporter) Report(err error, context map[string]string) {
	r.once.Do(r.async)

	select {
	case r.needles <- needle{err, context}:
	default:
	}
}

func (r *Reporter) async() {
	if r.MaxQueuedNeedles == 0 {
		r.MaxQueuedNeedles = 16
	}
	r.needles = make(chan needle, r.MaxQueuedNeedles)
	r.done = make(chan struct{})
	go func() {
		for needle := range r.needles {
			r.ReportBlocking(needle.err, needle.ctx)
		}
		close(r.done)
	}()
}

// ReportBlocking submits the given needle upstream. This function blocks until
// the needle has been successfuly sent, and returns an error otherwise.
//
// The keys and values passed in context will be added to the needle's payload
// before sending.
//
// If the needle was generated with the `errors` package, its full backtrace
// will be sent with the payload and the callsite of the error will be used as
// rollup key. If the needle is a generic error, no backtrace will be submitted
// and the error's message will be used as rollup key.
//
// See: Report for a non-blocking alternative.
func ReportBlocking(err error, context map[string]string) error {
	return DefaultReporter.ReportBlocking(err, context)
}

// ReportBlocking submits the given needle upstream. This function blocks until
// the needle has been successfuly sent, and returns an error otherwise.
//
// The keys and values passed in context will be added to the needle's payload
// before sending.
//
// If the needle was generated with the `errors` package, its full backtrace
// will be sent with the payload and the callsite of the error will be used as
// rollup key. If the needle is a generic error, no backtrace will be submitted
// and the error's message will be used as rollup key.
//
// See: Report for a non-blocking alternative.
func (r *Reporter) ReportBlocking(needle error, context map[string]string) error {
	payload := map[string]string{
		"app":     r.App,
		"host":    r.Hostname,
		"message": needle.Error(),
	}

	if err, ok := needle.(stackTracer); ok {
		bt := err.StackTrace()
		payload["backtrace"] = fmt.Sprintf("%+v", bt)

		top := bt[0]
		rollup := fmt.Sprintf("%+s:%d:%n", top, top, top)
		payload["rollup"] = r.rollup(rollup)
	} else {
		payload["rollup"] = r.rollup(needle.Error())
	}

	for k, v := range context {
		payload[k] = v
	}

	client := r.Client
	if client == nil {
		if r.URL == "" {
			client = defaultWriterClient
		} else {
			client = defaultHTTPClient
		}
	}

	b := bytes.Buffer{}
	json.NewEncoder(&b).Encode(payload)

	res, err := client.Post(r.URL, "application/json", &b)
	if res != nil {
		res.Body.Close()
	}

	if err != nil {
		return err
	}

	if res != nil && res.StatusCode != 201 {
		return errors.Errorf(
			"failed to report Haystack needle (http err: %d)",
			res.StatusCode)
	}

	return nil
}

func (r *Reporter) rollup(info string) string {
	hash := md5.New()
	io.WriteString(hash, info)
	return fmt.Sprintf("%x", hash.Sum(nil))
}
