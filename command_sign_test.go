package main

import (
	"crypto/x509"
	"testing"

	"github.com/github/ietf-cms"
	"github.com/github/ietf-cms/protocol"
	"github.com/stretchr/testify/require"
)

func chainContains(chain []*x509.Certificate, want *x509.Certificate) bool {
	for _, cert := range chain {
		if cert.Equal(want) {
			return true
		}
	}
	return false
}

func TestSign(t *testing.T) {
	defer testSetup(t, "--sign", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())
	sd, err := cms.ParseSignedData(stdoutBuf.Bytes())
	require.NoError(t, err)

	_, err = sd.Verify(x509.VerifyOptions{Roots: ca.ChainPool()})
	require.NoError(t, err)
}

func TestSignIncludeCertsAIA(t *testing.T) {
	defer testSetup(t, "--sign", "-u", certHexFingerprint(aiaLeaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 2, len(certs))
	require.True(t, chainContains(certs, aiaLeaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
}

func TestSignIncludeCertsDefault(t *testing.T) {
	defer testSetup(t, "--sign", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 2, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
}

func TestSignIncludeCertsMinus3(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=-3", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 2, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
}

func TestSignIncludeCertsMinus2(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=-2", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 2, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
}

func TestSignIncludeCertsMinus1(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=-1", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 3, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
	require.True(t, chainContains(certs, ca.Certificate))
}

func TestSignIncludeCerts0(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=0", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 0, len(certs))
}

func TestSignIncludeCerts1(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=1", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 1, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
}

func TestSignIncludeCerts2(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=2", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 2, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
}

func TestSignIncludeCerts3(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=3", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 3, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
	require.True(t, chainContains(certs, ca.Certificate))
}

func TestSignIncludeCerts4(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=4", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 3, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
	require.True(t, chainContains(certs, ca.Certificate))
}
