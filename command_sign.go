package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/mastahyeti/certstore"
	"github.com/mastahyeti/cms"
	"github.com/pkg/errors"
)

func commandSign() {
	userIdent, err := findUserIdentity()
	if err != nil {
		faile(err, "failed to get identity matching specified user-id")
	}
	if userIdent == nil {
		fail("Could not find identity matching specified user-id:", *localUserOpt)
	}

	// Git is looking for "\n[GNUPG:] SIG_CREATED ", meaning we need to print a
	// line before SIG_CREATED. BEGING_SIGNING seems appropraite. GPG emits this,
	// though GPGSM does not.
	sBeginSigning.emit()

	cert, err := userIdent.Certificate()
	if err != nil {
		faile(err, "failed to get idenity certificate")
	}

	signer, err := userIdent.Signer()
	if err != nil {
		faile(err, "failed to get idenity signer")
	}

	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, stdin); err != nil {
		faile(err, "failed to read message from stdin")
	}

	sd, err := cms.NewSignedData(dataBuf.Bytes())
	if err != nil {
		faile(err, "failed to create signed data")
	}
	if err = sd.Sign([]*x509.Certificate{cert}, signer); err != nil {
		faile(err, "failed to sign message")
	}
	if *detachSignFlag {
		sd.Detached()
	}

	if len(*tsaOpt) > 0 {
		if err = sd.AddTimestamps(*tsaOpt); err != nil {
			faile(err, "failed to add timestamp")
		}
	}

	chain, err := userIdent.CertificateChain()
	if err != nil {
		faile(err, "failed to get idenity certificate chain")
	}
	if err = sd.SetCertificates(certsForSignature(chain)); err != nil {
		faile(err, "failed to set certificates")
	}

	der, err := sd.ToDER()
	if err != nil {
		faile(err, "failed to serialize signature")
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
		fail("failed to write signature")
	}
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
		cert, err := ident.Certificate()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get identity certificate")
		}

		if certHasEmail(cert, email) || certHasFingerprint(cert, fpr) {
			return ident, nil
		}
	}

	return nil, nil
}

// certsForSignature determines which certificates to include in the signature
// based on the --include-certs option specified by the user.
func certsForSignature(chain []*x509.Certificate) []*x509.Certificate {
	if *includeCertsOpt <= -2 {
		if hasRoot := bytes.Equal(chain[len(chain)-1].RawIssuer, chain[len(chain)-1].RawSubject); hasRoot {
			return chain[0 : len(chain)-1]
		}
		return chain
	}

	if *includeCertsOpt == -1 {
		return chain
	}

	include := *includeCertsOpt
	if include > len(chain) {
		include = len(chain)
	}

	return chain[0:include]
}
