package cms

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
)

// UnsafeNoVerify instructs Verify and VerifyDetached not to verify signature's
// associated certificates against any set of trusted roots.
var UnsafeNoVerify = &x509.CertPool{}

// Verify verifies the SingerInfos' signatures. Each signature's associated
// certificate is verified using the provided roots. UnsafeNoVerify may be
// specified to skip this verification. Nil may be provided to use system roots.
// The certificates whose keys made the signatures are returned regardless of
// success.
func (sd *SignedData) Verify(roots *x509.CertPool) ([]*x509.Certificate, error) {
	data, err := sd.psd.EncapContentInfo.DataEContent()
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, errors.New("detached signature")
	}

	return sd.verify(data, roots)
}

// VerifyDetached verifies the SingerInfos' detached signatures over the
// provided message. Each signature's associated certificate is verified using
// the provided roots. UnsafeNoVerify may be specified to skip this
// verification. Nil may be provided to use system roots. The certificates whose
// keys made the signatures are returned regardless of success.
func (sd *SignedData) VerifyDetached(message []byte, roots *x509.CertPool) ([]*x509.Certificate, error) {
	if sd.psd.EncapContentInfo.EContent.Bytes != nil {
		return nil, errors.New("signature not detached")
	}

	return sd.verify(message, roots)
}

func (sd *SignedData) verify(message []byte, roots *x509.CertPool) ([]*x509.Certificate, error) {
	if len(sd.psd.SignerInfos) == 0 {
		return nil, errors.New("no signatures found")
	}

	certs, err := sd.psd.X509Certificates()
	if err != nil {
		return nil, err
	}

	verifyOpts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		Roots:         roots,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageCodeSigning,
		},
	}

	for _, cert := range certs {
		verifyOpts.Intermediates.AddCert(cert)
	}

	// Best effort attempt to gather all leaf certificates so we can return them
	// regardless of success.
	leafs := make([]*x509.Certificate, 0, len(sd.psd.SignerInfos))
	for _, si := range sd.psd.SignerInfos {
		if cert, err := si.FindCertificate(certs); err == nil {
			leafs = append(leafs, cert)
		}
	}

	for _, si := range sd.psd.SignerInfos {
		var signedMessage []byte

		// SignedAttrs is optional if EncapContentInfo eContentType isn't id-data.
		if si.SignedAttrs == nil {
			// If SignedAttrs is absent, validate that EncapContentInfo eContentType
			// is id-data.
			if _, err := sd.psd.EncapContentInfo.DataEContent(); err != nil {
				return nil, err
			}

			// If SignedAttrs is absent, the signature is over the original message
			// itself.
			signedMessage = message
		} else {
			// If SignedAttrs is present, we validate the mandatory ContentType and
			// MessageDigest attributes.
			siContentType, err := si.GetContentTypeAttribute()
			if err != nil {
				return nil, err
			}

			if !siContentType.Equal(sd.psd.EncapContentInfo.EContentType) {
				return nil, errors.New("invalid SignerInfo ContentType attribute")
			}

			// Calculate the digest over the actual message.
			hash := si.Hash()
			if hash == 0 {
				return nil, fmt.Errorf("unknown digest algorithm: %s", si.DigestAlgorithm.Algorithm.String())
			}
			if !hash.Available() {
				return nil, fmt.Errorf("Hash not avaialbe: %s", si.DigestAlgorithm.Algorithm.String())
			}
			actualMessageDigest := hash.New()
			if _, err = actualMessageDigest.Write(message); err != nil {
				return nil, err
			}

			// Get the digest from the SignerInfo.
			messageDigestAttr, err := si.GetMessageDigestAttribute()
			if err != nil {
				return nil, err
			}

			// Make sure message digests match.
			if !bytes.Equal(messageDigestAttr, actualMessageDigest.Sum(nil)) {
				return nil, errors.New("invalid message digest")
			}

			// The signature is over the DER encoded signed attributes, minus the
			// leading class/tag/length bytes. This includes the digest of the
			// original message, so it is implicitly signed too.
			if signedMessage, err = si.SignedAttrs.MarshaledForSigning(); err != nil {
				return nil, err
			}
		}

		cert, err := si.FindCertificate(certs)
		if err != nil {
			return nil, err
		}

		algo := si.X509SignatureAlgorithm()
		if algo == x509.UnknownSignatureAlgorithm {
			return nil, errors.New("unsupported signature or digest algorithm")
		}

		if err := cert.CheckSignature(algo, signedMessage, si.Signature); err != nil {
			return nil, err
		}

		if roots != UnsafeNoVerify {
			if _, err := cert.Verify(verifyOpts); err != nil {
				return nil, err
			}
		}
	}

	// OK
	return leafs, nil
}
