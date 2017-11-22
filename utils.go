package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"strings"
)

// normalizeFingerprint converts a string fingerprint to hex, removing leading
// "0x", if present.
func normalizeFingerprint(sfpr string) []byte {
	if len(sfpr) == 0 {
		return nil
	}

	if strings.HasPrefix(sfpr, "0x") {
		sfpr = sfpr[2:]
	}

	hfpr, err := hex.DecodeString(sfpr)
	if err != nil {
		return nil
	}

	return hfpr
}

// certHasFingerprint checks if the given certificate has the given fingerprint.
func certHasFingerprint(cert *x509.Certificate, fpr []byte) bool {
	if len(fpr) == 0 {
		return false
	}

	return bytes.HasSuffix(certFingerprint(cert), fpr)
}

// certHexFingerprint calculated the hex SHA1 fingerprint of a certificate.
func certHexFingerprint(cert *x509.Certificate) string {
	return hex.EncodeToString(certFingerprint(cert))
}

// certFingerprint calculated the SHA1 fingerprint of a certificate.
func certFingerprint(cert *x509.Certificate) []byte {
	if len(cert.Raw) == 0 {
		return nil
	}

	fpr := sha1.Sum(cert.Raw)
	return fpr[:]
}

// normalizeEmail attempts to extract an email address from a user-id string.
func normalizeEmail(email string) string {
	name, _, email := parseUserID(email)

	if len(email) > 0 {
		return email
	}

	if strings.ContainsRune(name, '@') {
		return name
	}

	return ""
}

// certHasEmail checks if a certificate contains the given email address in its
// subject (CN/emailAddress) or SAN fields.
func certHasEmail(cert *x509.Certificate, email string) bool {
	if len(email) == 0 {
		return false
	}

	// Check SAN
	for _, other := range cert.EmailAddresses {
		if other == email {
			return true
		}
	}

	// Check CN and emailAddress fields in cert subject.
	for _, name := range cert.Subject.Names {
		if !name.Type.Equal(oidEmailAddress) && !name.Type.Equal(oidCommonName) {
			continue
		}

		if other, isStr := name.Value.(string); isStr && other == email {
			return true
		}
	}

	return false
}
