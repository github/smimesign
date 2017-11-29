package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"

	"github.com/certifi/gocertifi"
	"github.com/mastahyeti/cms"
)

func commandVerify() {
	sNewSig.emit()

	if len(fileArgs) < 2 {
		verifyAttached()
	} else {
		verifyDetached()
	}
}

func verifyAttached() {
	var (
		f   *os.File
		err error
	)

	// Read in signature
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			failef(err, "failed to open signature file (%s)", fileArgs[0])
		}
		defer f.Close()
	} else {
		f = os.Stdin
	}

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		faile(err, "failed to read signature")
	}

	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		der = blk.Bytes
	} else {
		der = buf.Bytes()
	}

	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		faile(err, "failed to parse signature")
	}

	// Verify signature
	certs, err := sd.Verify(rootsPool())
	if err != nil {
		if len(certs) > 0 {
			emitBadSig(certs)
		} else {
			// TODO: We're ommitting a bunch of arguments here.
			sErrSig.emit()
		}

		faile(err, "failed to verify signature")
	}

	emitGoodSig(certs)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	emitTrustFully()
}

func verifyDetached() {
	// Read in signature
	f, err := os.Open(fileArgs[0])
	if err != nil {
		failef(err, "failed to open signature file (%s)", fileArgs[0])
	}
	defer f.Close()

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		faile(err, "failed to read signature file")
	}

	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		der = blk.Bytes
	} else {
		der = buf.Bytes()
	}

	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		faile(err, "failed to parse signature")
	}

	// Read in signed data
	if fileArgs[1] == "-" {
		f = os.Stdin
	} else {
		if f, err = os.Open(fileArgs[1]); err != nil {
			failef(err, "failed to open message file (%s)", fileArgs[1])
		}
		defer f.Close()
	}

	// Verify signature
	buf.Reset()
	if _, err = io.Copy(buf, f); err != nil {
		faile(err, "failed to read message file")
	}

	certs, err := sd.VerifyDetached(buf.Bytes(), rootsPool())
	if err != nil {
		if len(certs) > 0 {
			emitBadSig(certs)
		} else {
			// TODO: We're ommitting a bunch of arguments here.
			sErrSig.emit()
		}

		faile(err, "failed to verify signature")
	}

	emitGoodSig(certs)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	emitTrustFully()
}

func rootsPool() *x509.CertPool {
	roots, err := x509.SystemCertPool()
	if err != nil {
		// SystemCertPool isn't implemented for Windows. fall back to mozilla trust
		// store.
		roots, err = gocertifi.CACerts()
		if err != nil {
			// Fall back to an empty store. Verification will likely fail.
			roots = x509.NewCertPool()
		}
	}

	for _, ident := range idents {
		if cert, err := ident.Certificate(); err == nil {
			roots.AddCert(cert)
		}
	}

	return roots
}
