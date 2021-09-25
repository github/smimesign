package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/github/certstore"
	"github.com/github/smimesign/pinentry"
	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
)

// PivIdentities enumerates identities stored in the signature slot inside hardware keys
func PivIdentities() ([]PivIdentity, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	var identities []PivIdentity
	for _, card := range cards {
		yk, err := piv.Open(card)
		if err != nil {
			continue
		}
		cert, err := yk.Certificate(piv.SlotSignature)
		if err != nil {
			continue
		}
		if cert != nil {
			ident := PivIdentity{card: card, yk: yk}
			identities = append(identities, ident)
		}
	}
	return identities, nil
}

// PivIdentity is an entity identity stored in a hardware key PIV applet
type PivIdentity struct {
	card string
	//pin  string
	yk *piv.YubiKey
}

var _ certstore.Identity = (*PivIdentity)(nil)
var _ crypto.Signer = (*PivIdentity)(nil)

// Certificate implements the certstore.Identity interface
func (ident *PivIdentity) Certificate() (*x509.Certificate, error) {
	return ident.yk.Certificate(piv.SlotSignature)
}

// CertificateChain implements the certstore.Identity interface
func (ident *PivIdentity) CertificateChain() ([]*x509.Certificate, error) {
	cert, err := ident.Certificate()
	if err != nil {
		return nil, err
	}

	return []*x509.Certificate{cert}, nil
}

// Signer implements the certstore.Identity interface
func (ident *PivIdentity) Signer() (crypto.Signer, error) {
	return ident, nil
}

// Delete implements the certstore.Identity interface
func (ident *PivIdentity) Delete() error {
	panic("deleting identities on PIV applet is not supported")
}

// Close implements the certstore.Identity interface
func (ident *PivIdentity) Close() {
	_ = ident.yk.Close()
}

// Public implements the crypto.Signer interface
func (ident *PivIdentity) Public() crypto.PublicKey {
	cert, err := ident.Certificate()
	if err != nil {
		return nil
	}

	return cert.PublicKey
}

// Sign implements the crypto.Signer interface
func (ident *PivIdentity) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	entry, err := pinentry.NewPinentry()
	if err != nil {
		return nil, err
	}

	pin, err := entry.Get(fmt.Sprintf("Enter PIN for \"%v\"", ident.card))
	if err != nil {
		return nil, err
	}
	private, err := ident.yk.PrivateKey(piv.SlotSignature, ident.Public(), piv.KeyAuth{
		PIN: pin,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get private key for signing")
	}

	switch private.(type) {
	case *piv.ECDSAPrivateKey:
		return private.(*piv.ECDSAPrivateKey).Sign(rand, digest, opts)
	default:
		return nil, fmt.Errorf("invalid key type")
	}
}
