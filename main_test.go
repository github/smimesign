package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"os"
	"testing"

	"github.com/github/smimesign/certstore"
	"github.com/github/smimesign/fakeca"
	"github.com/pborman/getopt/v2"
)

var (
	ca           = fakeca.New(fakeca.IsCA)
	intermediate = ca.Issue(fakeca.IsCA)
	leaf         = intermediate.Issue()
	aiaLeaf      = intermediate.Issue(fakeca.IssuingCertificateURL("http://foo"))

	wrappedLeaf    = identity{leaf}
	wrappedAIALeaf = identity{aiaLeaf}
)

// make *fakeca.Identity implement certstore.Identity
type identity struct {
	*fakeca.Identity
}

func (i identity) Certificate() (*x509.Certificate, error) {
	return i.Identity.Certificate, nil
}

func (i identity) CertificateChain() ([]*x509.Certificate, error) {
	return i.Chain(), nil
}

func (i identity) Signer() (crypto.Signer, error) {
	return i.PrivateKey, nil
}

func (i identity) Delete() error {
	return errors.New("not implemented")
}

func (i identity) Close() {}

func TestMain(m *testing.M) {
	resetIO()
	os.Exit(m.Run())
}

type BufferCloser struct {
	*bytes.Buffer
}

func (bc BufferCloser) Close() error {
	return nil
}

var (
	stdinBuf  *bytes.Buffer
	stdoutBuf *bytes.Buffer
	stderrBuf *bytes.Buffer
)

func resetIO() {
	stdinBuf = new(bytes.Buffer)
	stdoutBuf = new(bytes.Buffer)
	stderrBuf = new(bytes.Buffer)

	stdin = BufferCloser{stdinBuf}
	stdout = BufferCloser{stdoutBuf}
	stderr = BufferCloser{stderrBuf}
}

// setup for a test
//
// - parses provided args
// - sets the failer to be a function that fails the test. returns a reset
//   function that should be deferred.
//
// Example:
//   func TestFoo(t *testing.T) {
//     defer testSetup(t, "--sign")()
//     ...
//   }
func testSetup(t *testing.T, args ...string) func() {
	t.Helper()

	resetFunc := func() {
		resetIO()
		getopt.Reset()
	}

	getopt.CommandLine.Parse(append([]string{"smimesign"}, args...))

	idents = []certstore.Identity{
		wrappedLeaf,
		wrappedAIALeaf,
	}

	return resetFunc
}
