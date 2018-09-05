package haystack

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type FakeHaystack struct {
	Payloads []map[string]string
	server   *httptest.Server
}

func (s *FakeHaystack) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/needles" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Invalid Method", http.StatusBadRequest)
		return
	}

	var payload map[string]string
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON Body", http.StatusBadRequest)
		return
	}

	s.Payloads = append(s.Payloads, payload)
	w.WriteHeader(201)
}

func (s *FakeHaystack) ServerURL() string {
	if s.server == nil {
		s.server = httptest.NewServer(s)
	}
	return s.server.URL + "/api/needles"
}

func (s *FakeHaystack) Client() *Reporter {
	return &Reporter{
		URL:      s.ServerURL(),
		Hostname: "localhost",
		App:      "test-suite",
	}
}

func (s *FakeHaystack) Stop() {
	if s.server != nil {
		s.server.Close()
	}
}

func TestNoNeedlesWontPanic(t *testing.T) {
	reporter := Reporter{}
	reporter.Close()
}

func TestReporting(t *testing.T) {
	haystack := &FakeHaystack{}
	defer haystack.Stop()

	client := haystack.Client()
	err := GetAnError(3)

	assert.NoError(t, client.ReportBlocking(err, nil))
	assert.Equal(t, 1, len(haystack.Payloads))

	payload := haystack.Payloads[0]
	assert.Equal(t, "localhost", payload["host"])
	assert.Equal(t, "test-suite", payload["app"])
	assert.Equal(t, "This is error 3", payload["message"])
	assert.Contains(t, payload["backtrace"], "error_test.go:34")
	t.Log(payload["backtrace"])
}

func TestAsyncReporting(t *testing.T) {
	haystack := &FakeHaystack{}
	defer haystack.Stop()

	client := haystack.Client()
	client.Report(GetAnError(1), nil)
	client.Close()

	assert.Equal(t, 1, len(haystack.Payloads))
}

func TestReportPanics(t *testing.T) {
	haystack := &FakeHaystack{}
	defer haystack.Stop()

	client := haystack.Client()
	PanicRecover(client)

	assert.Equal(t, 1, len(haystack.Payloads))
	payload := haystack.Payloads[0]
	assert.Contains(t, payload["backtrace"], "error_test.go:6")
	t.Log(payload["backtrace"])
}

func TestRollups(t *testing.T) {
	haystack := &FakeHaystack{}
	defer haystack.Stop()

	client := haystack.Client()

	assert.NoError(t, client.ReportBlocking(GetAnError(1), nil))
	assert.NoError(t, client.ReportBlocking(GetAnError(2), nil))
	assert.NoError(t, client.ReportBlocking(GetAnError(3), nil))
	assert.NoError(t, client.ReportBlocking(GetAnError(1), nil))

	assert.Equal(t, 4, len(haystack.Payloads))

	assert.NotEqual(t, haystack.Payloads[0]["rollup"], haystack.Payloads[1]["rollup"])
	assert.NotEqual(t, haystack.Payloads[0]["rollup"], haystack.Payloads[2]["rollup"])
	assert.Equal(t, haystack.Payloads[0]["rollup"], haystack.Payloads[3]["rollup"])
}

func TestDefaultReporting(t *testing.T) {
	haystack := &FakeHaystack{}
	defer haystack.Stop()

	DefaultReporter.URL = haystack.ServerURL()

	assert.NoError(t, ReportBlocking(GetAnError(1), nil))

	assert.Equal(t, 1, len(haystack.Payloads))
	payload := haystack.Payloads[0]
	assert.NotEqual(t, "", payload["host"])
	assert.Equal(t, "", payload["app"])
	assert.Equal(t, "This is error 1", payload["message"])
	assert.Contains(t, payload["backtrace"], "error_test.go:28")
}

func TestDefaultWriterNeedle(t *testing.T) {
	haystack := &FakeHaystack{}
	defer haystack.Stop()

	var fakeWriter bytes.Buffer
	defaultWriterClient.out = &fakeWriter
	DefaultReporter.URL = ""
	ReportBlocking(GetAnError(1), nil)

	assert.Equal(t, bytes.Contains(fakeWriter.Bytes(), []byte("Needle:")), true)
	assert.Equal(t, bytes.Contains(fakeWriter.Bytes(), []byte("\"backtrace\":")), true)
	assert.Equal(t, bytes.Contains(fakeWriter.Bytes(), []byte("\"This is error 1\"")), true)
}
