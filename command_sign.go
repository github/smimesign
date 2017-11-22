package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mastahyeti/certstore"
	"github.com/mastahyeti/cms"
)

var (
	oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidCommonName   = asn1.ObjectIdentifier{2, 5, 4, 3}
)

func commandSign() int {
	store, err := certstore.Open()
	if err != nil {
		panic(err)
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		panic(err)
	}
	for _, ident := range idents {
		defer ident.Close()
	}

	userIdent, err := findUserIdentity(idents)
	if err != nil {
		panic(err)
	}
	if userIdent == nil {
		fmt.Printf("Could not find identity matching specified user-id: %s\n", *localUserOpt)
		return 1
	}

	cert, err := userIdent.Certificate()
	if err != nil {
		panic(err)
	}

	signer, err := userIdent.Signer()
	if err != nil {
		panic(err)
	}

	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, os.Stdin); err != nil {
		panic(err)
	}

	var der []byte
	if *detachSignFlag {
		der, err = cms.SignDetached(dataBuf.Bytes(), cert, signer)
	} else {
		der, err = cms.Sign(dataBuf.Bytes(), cert, signer)
	}
	if err != nil {
		panic(err)
	}

	// SIG_CREATED
	emitSigCreated(cert, *detachSignFlag)

	if *armorFlag {
		err = pem.Encode(os.Stdout, &pem.Block{
			Type:  "SIGNED MESSAGE",
			Bytes: der,
		})
	} else {
		_, err = os.Stdout.Write(der)
	}
	if err != nil {
		panic(err)
	}

	return 0
}

// findUserIdentity attempts to find an identity to sign with in the certstore
// by checking available identities against the --local-user argument.
func findUserIdentity(idents []certstore.Identity) (certstore.Identity, error) {
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
			return nil, err
		}

		if certHasEmail(cert, email) || certHasFingerprint(cert, fpr) {
			return ident, nil
		}
	}

	return nil, nil
}
