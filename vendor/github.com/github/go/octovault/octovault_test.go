package octovault_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/github/go/octovault"
)

func TestGetSecrets(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	ov := octovault.New(octovault.Config{
		VaultSocket: ts.Socket,
	})

	secrets, err := ov.GetSecrets("octoawesome", "production")
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	if len(secrets) != 2 {
		t.Errorf("expected 2 secrets, got %d", len(secrets))
	}

	if secrets["blah"] != "ok" {
		t.Error("incorrect secret for key blah")
	}

	if secrets["foo"] != "bar" {
		t.Error("incorrect secret for foo")
	}
}

func TestGetSecret(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	ov := octovault.New(octovault.Config{
		VaultSocket: ts.Socket,
	})
	secret, err := ov.GetSecret("octoawesome", "production", "foo")
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	if secret != "bar" {
		t.Error("incorrect secret for foo")
	}
}

func TestGetRoleSecrets(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	ov := octovault.New(octovault.Config{
		VaultSocket: ts.Socket,
	})

	secrets, err := ov.GetRoleSecrets("octoawesome", "role", "production")
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	if len(secrets) != 2 {
		t.Errorf("expected 2 secrets, got %d", len(secrets))
	}

	if secrets["blah"] != "ok" {
		t.Error("incorrect secret for key blah")
	}

	if secrets["foo"] != "bar" {
		t.Error("incorrect secret for foo")
	}
}

func TestGetRoleSecret(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	ov := octovault.New(octovault.Config{
		VaultSocket: ts.Socket,
	})
	secret, err := ov.GetRoleSecret("octoawesome", "role", "production", "foo")
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	if secret != "bar" {
		t.Error("incorrect secret for foo")
	}
}

type testServer struct {
	Socket string
	l      net.Listener
	s      *http.Server
}

func newTestServer() *testServer {
	l, err := net.Listen("unix", "")
	if err != nil {
		panic(fmt.Sprintf("failed to listen: %v", err.Error()))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/apps/octoawesome/production", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"blah":"ok","foo":"bar"}`))
	})

	mux.HandleFunc("/v1/apps/octoawesome/production/foo", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"foo":"bar"}`))
	})
	mux.HandleFunc("/v1/gh_app/octoawesome/role/production", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"blah":"ok","foo":"bar"}`))
	})

	mux.HandleFunc("/v1/gh_app/octoawesome/role/production/foo", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"foo":"bar"}`))
	})

	s := &http.Server{Handler: mux}
	go s.Serve(l)

	return &testServer{
		Socket: l.Addr().String(),
		l:      l,
		s:      s,
	}
}

func (s *testServer) Close() {
	s.s.Shutdown(context.Background())
}
