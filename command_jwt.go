package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

func commandJwt() error {
	userIdent, err := findUserIdentity()
	if err != nil {
		return errors.Wrap(err, "failed to get identity matching specified user-id")
	}
	if userIdent == nil {
		return fmt.Errorf("could not find identity matching specified user-id: %s", *localUserOpt)
	}

	cert, err := userIdent.Certificate()
	if err != nil {
		return errors.Wrap(err, "failed to get identity certificate")
	}

	signer, err := userIdent.Signer()
	if err != nil {
		return errors.Wrap(err, "failed to get identity signer")
	}

	method, hash, err := getX509JwtSigningMethod(cert)
	if err != nil {
		return errors.Wrap(err, "failed to get JWT signing method")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return errors.New("failed to create new UUID for JWT")
	}

	token := jwt.NewWithClaims(method, jwt.RegisteredClaims{
		Issuer:    cert.Issuer.String(),
		Subject:   cert.Subject.String(),
		Audience:  []string{},
		ExpiresAt: &jwt.NumericDate{cert.NotAfter},
		NotBefore: &jwt.NumericDate{cert.NotBefore},
		IssuedAt:  &jwt.NumericDate{cert.NotBefore},
		ID:        id.String(),
	})

	signingString, err := token.SigningString()

	if !hash.Available() {
		return fmt.Errorf("hash function not available: %s", hash)
	}

	hasher := hash.New()

	_, err = hasher.Write([]byte(signingString))
	if err != nil {
		return errors.Wrap(err, "failed to create digest")
	}

	sigBytes, err := signer.Sign(rand.Reader, hasher.Sum(nil), hash)
	if err != nil {
		return errors.Wrap(err, "failed to sign JWT")
	}

	signedJwt := strings.Join([]string{signingString, jwt.EncodeSegment(sigBytes)}, ".")

	_, err = stdout.Write([]byte(signedJwt))

	return nil
}

// convert x509.SignatureAlgorithm to jwt.SigningMethod
func getX509JwtSigningMethod(cert *x509.Certificate) (method jwt.SigningMethod, hash crypto.Hash, err error) {
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		method = jwt.SigningMethodRS256
		hash = jwt.SigningMethodRS256.Hash
	case x509.SHA384WithRSA:
		method = jwt.SigningMethodRS384
		hash = jwt.SigningMethodRS384.Hash
	case x509.SHA512WithRSA:
		method = jwt.SigningMethodRS512
		hash = jwt.SigningMethodRS512.Hash
	case x509.SHA256WithRSAPSS:
		method = jwt.SigningMethodPS256
		hash = jwt.SigningMethodPS256.Hash
	case x509.SHA384WithRSAPSS:
		method = jwt.SigningMethodPS384
		hash = jwt.SigningMethodPS384.Hash
	case x509.SHA512WithRSAPSS:
		method = jwt.SigningMethodPS512
		hash = jwt.SigningMethodPS512.Hash
	case x509.ECDSAWithSHA256:
		method = jwt.SigningMethodES256
		hash = jwt.SigningMethodES256.Hash
	case x509.ECDSAWithSHA384:
		method = jwt.SigningMethodES384
		hash = jwt.SigningMethodES384.Hash
	case x509.ECDSAWithSHA512:
		method = jwt.SigningMethodES512
		hash = jwt.SigningMethodES512.Hash
	case x509.PureEd25519:
		// Ed25519 does not implement crypto.Hash, so it is more difficult to implement
		// method = jwt.SigningMethodEdDSA
		err = errors.New("the Ed25519 algorithm is not currently supported by smimesign")
	case x509.DSAWithSHA1, x509.DSAWithSHA256:
		err = errors.New("the DSA algorithm is not supported by JWT")
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		err = errors.New("the SHA1 hashing algorithm is not supported by JWT")
	case x509.MD2WithRSA, x509.MD5WithRSA:
		err = errors.New("the MD hashing algorithm family is not supported by JWT")
	default:
		err = errors.New("could not parse the x509 signature algorithm")
	}

	return
}
