package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"regexp"
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

var (
	oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidCommonName   = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// certHasEmail checks if a certificate contains the given email address in its
// subject (CN/emailAddress) or SAN fields.
func certHasEmail(cert *x509.Certificate, email string) bool {
	for _, other := range certEmails(cert) {
		if other == email {
			return true
		}
	}

	return false
}

// borrowed from http://emailregex.com/
var emailRegexp = regexp.MustCompile(`(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)`)

// certEmails extracts email addresses from a certificate's subject
// (CN/emailAddress) and SAN extensions.
func certEmails(cert *x509.Certificate) []string {
	// From SAN
	emails := cert.EmailAddresses

	// From CN and emailAddress fields in subject.
	for _, name := range cert.Subject.Names {
		if !name.Type.Equal(oidEmailAddress) && !name.Type.Equal(oidCommonName) {
			continue
		}

		if email, isStr := name.Value.(string); isStr && emailRegexp.MatchString(email) {
			emails = append(emails, email)
		}
	}

	return emails
}

// keyUsageNames contains the mapping between a KeyUsage and its Name.
var keyUsageNames = []struct {
	keyUsage x509.KeyUsage
	name     string
}{
	{x509.KeyUsageDigitalSignature, "DigitalSignature"},
	{x509.KeyUsageContentCommitment, "ContentCommitment"},
	{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
	{x509.KeyUsageDataEncipherment, "DataEncipherment"},
	{x509.KeyUsageKeyAgreement, "KeyAgreement"},
	{x509.KeyUsageCertSign, "CertSign"},
	{x509.KeyUsageCRLSign, "CRLSign"},
	{x509.KeyUsageEncipherOnly, "EncipherOnly"},
	{x509.KeyUsageDecipherOnly, "DecipherOnly"},
}

func keyUsageToNames(ku x509.KeyUsage) []string {

	var kus []string

	for _, k2n := range keyUsageNames {
		if !(int(k2n.keyUsage)&int(ku) == 0) {
			kus = append(kus, k2n.name)
		}
	}

	return kus
}

// extKeyUsageNames contains the mapping between an ExtKeyUsage and its Name.
var extKeyUsageNames = []struct {
	extKeyUsage x509.ExtKeyUsage
	name        string
}{
	{x509.ExtKeyUsageAny, "Any"},
	{x509.ExtKeyUsageServerAuth, "ServerAuth"},
	{x509.ExtKeyUsageClientAuth, "ClientAuth"},
	{x509.ExtKeyUsageCodeSigning, "CodeSigning"},
	{x509.ExtKeyUsageEmailProtection, "EmailProtection"},
	{x509.ExtKeyUsageIPSECEndSystem, "IPSECEndSystem"},
	{x509.ExtKeyUsageIPSECTunnel, "IPSECTunnel"},
	{x509.ExtKeyUsageIPSECUser, "IPSECUser"},
	{x509.ExtKeyUsageTimeStamping, "TimeStamping"},
	{x509.ExtKeyUsageOCSPSigning, "OCSPSigning"},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, "MicrosoftServerGatedCrypto"},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, "NetscapeServerGatedCrypto"},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, "MicrosoftCommercialCodeSigning"},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, "MicrosoftKernelCodeSigning"},
}

// extKeyUsageToName take an ExtKeyUsage and returns its name
func extKeyUsageToName(eku x509.ExtKeyUsage) (name string) {
	for _, pair := range extKeyUsageNames {
		if eku == pair.extKeyUsage {
			return pair.name
		}
	}
	return
}

// certExtKeyUsages extracts Key Usage fields from a certificate and returns them as string.
func certExtKeyUsages(cert *x509.Certificate) []string {

	var ekus []string

	for _, eku := range cert.ExtKeyUsage {
		ekus = append(ekus, extKeyUsageToName(eku))
	}

	return ekus

}
