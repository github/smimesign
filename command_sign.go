package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/github/certstore"
	"github.com/github/ietf-cms"
	"github.com/pkg/errors"
)

func commandSign() error {
	userIdent, err := findUserIdentity()
	if err != nil {
		return errors.Wrap(err, "failed to get identity matching specified user-id")
	}
	if userIdent == nil {
		return fmt.Errorf("could not find identity matching specified user-id: %s", *localUserOpt)
	}

	cert, err := userIdent.Certificate()
	if err != nil {
		return errors.Wrap(err, "failed to get idenity certificate")
	}

	signer, err := userIdent.Signer()
	if err != nil {
		return errors.Wrap(err, "failed to get idenity signer")
	}

	var f io.ReadCloser
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			return errors.Wrapf(err, "failed to open message file (%s)", fileArgs[0])
		}
		defer f.Close()
	} else {
		f = stdin
	}

	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, f); err != nil {
		return errors.Wrap(err, "failed to read message from stdin")
	}

	sd, err := cms.NewSignedData(dataBuf.Bytes())
	if err != nil {
		return errors.Wrap(err, "failed to create signed data")
	}
	if err = sd.Sign([]*x509.Certificate{cert}, signer); err != nil {
		return errors.Wrap(err, "failed to sign message")
	}
	// Git is looking for "\n[GNUPG:] SIG_CREATED ", meaning we need to print a
	// line before SIG_CREATED. BEGIN_SIGNING seems appropraite. GPG emits this,
	// though GPGSM does not.
	sBeginSigning.emit()
	if *detachSignFlag {
		sd.Detached()
	}

	if len(*tsaOpt) > 0 {
		if err = sd.AddTimestamps(*tsaOpt); err != nil {
			return errors.Wrap(err, "failed to add timestamp")
		}
	}

	chain, err := userIdent.CertificateChain()
	if err != nil {
		return errors.Wrap(err, "failed to get idenity certificate chain")
	}
	if chain, err = certsForSignature(chain); err != nil {
		return err
	}
	if err = sd.SetCertificates(chain); err != nil {
		return errors.Wrap(err, "failed to set certificates")
	}

	der, err := sd.ToDER()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signature")
	}

	emitSigCreated(cert, *detachSignFlag)

	if *armorFlag {
		err = pem.Encode(stdout, &pem.Block{
			Type:  "SIGNED MESSAGE",
			Bytes: der,
		})
	} else {
		_, err = stdout.Write(der)
	}
	if err != nil {
		return errors.New("failed to write signature")
	}

	return nil
}

// findUserIdentity attempts to find an identity to sign with in the certstore
// by checking available identities against the --local-user argument.
func findUserIdentity() (certstore.Identity, error) {
	var (
		email string
		fpr   []byte
	)

	if strings.ContainsRune(*localUserOpt, '@') {
		email = normalizeEmail(*localUserOpt)
	} else {
		fpr = normalizeFingerprint(*localUserOpt)
	}

	if len(email) == 0 && len(fpr) == 0 {
		return nil, fmt.Errorf("bad user-id format: %s", *localUserOpt)
	}

	for _, ident := range idents {
		if cert, err := ident.Certificate(); err == nil && (certHasEmail(cert, email) || certHasFingerprint(cert, fpr)) {
			return ident, nil
		}
	}

	return nil, nil
}

// certsForSignature determines which certificates to include in the signature
// based on the --include-certs option specified by the user.
func certsForSignature(chain []*x509.Certificate) ([]*x509.Certificate, error) {
	include := *includeCertsOpt

	if include < -3 {
		include = -2 // default
	}
	if include > len(chain) {
		include = len(chain)
	}

	switch include {
	case -3:
		for i := len(chain) - 1; i > 0; i-- {
			issuer, cert := chain[i], chain[i-1]

			// remove issuer when cert has AIA extension
			if bytes.Equal(issuer.RawSubject, cert.RawIssuer) && len(cert.IssuingCertificateURL) > 0 {
				chain = chain[0:i]
			}
		}
		return chainWithoutRoot(chain), nil
	case -2:
		return chainWithoutRoot(chain), nil
	case -1:
		return chain, nil
	default:
		return chain[0:include], nil
	}
}

// Returns the provided chain, having removed the root certificate, if present.
// This includes removing the cert itself if the chain is a single self-signed
// cert.
func chainWithoutRoot(chain []*x509.Certificate) []*x509.Certificate {
	if len(chain) == 0 {
		return chain
	}

	lastIdx := len(chain) - 1
	last := chain[lastIdx]

	if bytes.Equal(last.RawIssuer, last.RawSubject) {
		return chain[0:lastIdx]
	}

	return chain
}
