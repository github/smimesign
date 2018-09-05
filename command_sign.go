package main

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mastahyeti/certstore"
	"github.com/mastahyeti/cms"
	"github.com/pkg/errors"
)

func commandSign() error {
	userIdent, err := findUserIdentity()
	if err != nil {
		return errors.Wrap(err, "failed to get identity matching specified user-id")
	}
	if userIdent == nil {
		return fmt.Errorf("Could not find identity matching specified user-id: %s\n", *localUserOpt)
	}

	// Git is looking for "\n[GNUPG:] SIG_CREATED ", meaning we need to print a
	// line before SIG_CREATED. BEGING_SIGNING seems appropraite. GPG emits this,
	// though GPGSM does not.
	sBeginSigning.emit()

	chain, err := userIdent.CertificateChain()
	if err != nil {
		return errors.Wrap(err, "failed to get idenity certificate chain")
	}

	signer, err := userIdent.Signer()
	if err != nil {
		return errors.Wrap(err, "failed to get idenity signer")
	}

	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, os.Stdin); err != nil {
		return errors.Wrap(err, "failed to read message from stdin")
	}

	sd, err := cms.NewSignedData(dataBuf.Bytes())
	if err != nil {
		return errors.Wrap(err, "failed to create signed data")
	}
	if err := sd.Sign(chain, signer); err != nil {
		return errors.Wrap(err, "failed to sign message")
	}
	if *detachSignFlag {
		sd.Detached()
	}

	if len(*tsaOpt) > 0 {
		if err = sd.AddTimestamps(*tsaOpt); err != nil {
			return errors.Wrap(err, "failed to add timestamp")
		}
	}

	der, err := sd.ToDER()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signature")
	}

	emitSigCreated(chain[0], *detachSignFlag)

	if *armorFlag {
		err = pem.Encode(os.Stdout, &pem.Block{
			Type:  "SIGNED MESSAGE",
			Bytes: der,
		})
	} else {
		_, err = os.Stdout.Write(der)
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
