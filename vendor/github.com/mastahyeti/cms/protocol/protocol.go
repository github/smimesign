// Package protocol implements low level CMS types, parsing and generation.
package protocol

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	_ "crypto/sha1" // for crypto.SHA1
)

var (
	// ErrUnsupportedContentType is returned when a CMS content is not supported.
	// Currently only Data (1.2.840.113549.1.7.1) and
	// Signed Data (1.2.840.113549.1.7.2) are supported.
	ErrUnsupportedContentType = errors.New("cms/protocol: cannot parse data: unimplemented content type")

	// ErrWrongType is returned by methods that make assumptions about types.
	// Helper methods are defined for accessing CHOICE and  ANY feilds. These
	// helper methods get the value of the field, assuming it is of a given type.
	// This error is returned if that assumption is wrong and the field has a
	// different type.
	ErrWrongType = errors.New("cms/protocol: wrong choice or any type")
)

var (
	nilOID = asn1.ObjectIdentifier(nil)

	// Content type OIDs
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// Attribute OIDs
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Signature Algorithm  OIDs
	oidSignatureAlgorithmRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSignatureAlgorithmECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	// Digest Algorithm OIDs
	oidDigestAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidDigestAlgorithmMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// X509 extensions
	oidSubjectKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 14}

	// digestAlgorithmToHash maps digest OIDs to crypto.Hash values.
	digestAlgorithmToHash = map[string]crypto.Hash{
		oidDigestAlgorithmSHA1.String():   crypto.SHA1,
		oidDigestAlgorithmMD5.String():    crypto.MD5,
		oidDigestAlgorithmSHA256.String(): crypto.SHA256,
		oidDigestAlgorithmSHA384.String(): crypto.SHA384,
		oidDigestAlgorithmSHA512.String(): crypto.SHA512,
	}

	// signatureAlgorithmToDigestAlgorithm maps x509.SignatureAlgorithm to
	// digestAlgorithm OIDs.
	signatureAlgorithmToDigestAlgorithm = map[x509.SignatureAlgorithm]asn1.ObjectIdentifier{
		x509.SHA1WithRSA:     oidDigestAlgorithmSHA1,
		x509.MD5WithRSA:      oidDigestAlgorithmMD5,
		x509.SHA256WithRSA:   oidDigestAlgorithmSHA256,
		x509.SHA384WithRSA:   oidDigestAlgorithmSHA384,
		x509.SHA512WithRSA:   oidDigestAlgorithmSHA512,
		x509.ECDSAWithSHA1:   oidDigestAlgorithmSHA1,
		x509.ECDSAWithSHA256: oidDigestAlgorithmSHA256,
		x509.ECDSAWithSHA384: oidDigestAlgorithmSHA384,
		x509.ECDSAWithSHA512: oidDigestAlgorithmSHA512,
	}

	// signatureAlgorithmToSignatureAlgorithm maps x509.SignatureAlgorithm to
	// signatureAlgorithm OIDs.
	signatureAlgorithmToSignatureAlgorithm = map[x509.SignatureAlgorithm]asn1.ObjectIdentifier{
		x509.SHA1WithRSA:     oidSignatureAlgorithmRSA,
		x509.MD5WithRSA:      oidSignatureAlgorithmRSA,
		x509.SHA256WithRSA:   oidSignatureAlgorithmRSA,
		x509.SHA384WithRSA:   oidSignatureAlgorithmRSA,
		x509.SHA512WithRSA:   oidSignatureAlgorithmRSA,
		x509.ECDSAWithSHA1:   oidSignatureAlgorithmECDSA,
		x509.ECDSAWithSHA256: oidSignatureAlgorithmECDSA,
		x509.ECDSAWithSHA384: oidSignatureAlgorithmECDSA,
		x509.ECDSAWithSHA512: oidSignatureAlgorithmECDSA,
	}

	// signatureAlgorithms maps digest and signature OIDs to
	// x509.SignatureAlgorithm values.
	signatureAlgorithms = map[string]map[string]x509.SignatureAlgorithm{
		oidSignatureAlgorithmRSA.String(): map[string]x509.SignatureAlgorithm{
			oidDigestAlgorithmSHA1.String():   x509.SHA1WithRSA,
			oidDigestAlgorithmMD5.String():    x509.MD5WithRSA,
			oidDigestAlgorithmSHA256.String(): x509.SHA256WithRSA,
			oidDigestAlgorithmSHA384.String(): x509.SHA384WithRSA,
			oidDigestAlgorithmSHA512.String(): x509.SHA512WithRSA,
		},
		oidSignatureAlgorithmECDSA.String(): map[string]x509.SignatureAlgorithm{
			oidDigestAlgorithmSHA1.String():   x509.ECDSAWithSHA1,
			oidDigestAlgorithmSHA256.String(): x509.ECDSAWithSHA256,
			oidDigestAlgorithmSHA384.String(): x509.ECDSAWithSHA384,
			oidDigestAlgorithmSHA512.String(): x509.ECDSAWithSHA512,
		},
	}
)

// ContentInfo ::= SEQUENCE {
//   contentType ContentType,
//   content [0] EXPLICIT ANY DEFINED BY contentType }
//
// ContentType ::= OBJECT IDENTIFIER
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// ParseContentInfo parses a top-level ContentInfo type from BER encoded data.
func ParseContentInfo(ber []byte) (ci ContentInfo, err error) {
	var der []byte
	if der, err = ber2der(ber); err != nil {
		return
	}

	var rest []byte
	if rest, err = asn1.Unmarshal(der, &ci); err != nil {
		return
	}
	if len(rest) > 0 {
		err = errors.New("unexpected trailing data")
	}

	return
}

// SignedDataContent gets the content assuming contentType is signedData.
func (ci ContentInfo) SignedDataContent() (*SignedData, error) {
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, ErrWrongType
	}

	sd := new(SignedData)
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, sd); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("unexpected trailing data")
	}

	return sd, nil
}

// EncapsulatedContentInfo ::= SEQUENCE {
//   eContentType ContentType,
//   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
//
// ContentType ::= OBJECT IDENTIFIER
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// NewDataEncapsulatedContentInfo creates a new EncapsulatedContentInfo of type
// id-data.
func NewDataEncapsulatedContentInfo(data []byte) (EncapsulatedContentInfo, error) {
	octetString, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagOctetString,
		Bytes:      data,
		IsCompound: false,
	})
	if err != nil {
		return EncapsulatedContentInfo{}, err
	}

	return EncapsulatedContentInfo{
		EContentType: oidData,
		EContent: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      octetString,
			IsCompound: true,
		},
	}, nil
}

// DataEContent gets the EContent assuming EContentType is data. A nil byte
// slice is returned if the OPTIONAL eContent field is missing.
func (eci EncapsulatedContentInfo) DataEContent() ([]byte, error) {
	if !eci.EContentType.Equal(oidData) {
		return nil, ErrWrongType
	}
	if eci.EContent.Bytes == nil {
		return nil, nil
	}

	var data asn1.RawValue
	if rest, err := asn1.Unmarshal(eci.EContent.Bytes, &data); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("unexpected trailing data")
	}
	if data.Class != asn1.ClassUniversal || data.Tag != asn1.TagOctetString {
		return nil, fmt.Errorf("bad data content (class: %d tag: %d)", data.Class, data.Tag)
	}

	var dataValue []byte

	// gpgsm uses a constructed OCTET STRING for the data. Constructed, as opposed
	// to primitive, strings are only allowed in BER encoding. Our ber2der stuff
	// doesn't handle this, so we do it manually.
	if data.IsCompound {
		rest := data.Bytes
		for len(rest) > 0 {
			var err error
			if rest, err = asn1.Unmarshal(rest, &data); err != nil {
				return nil, err
			}

			// Don't allow further constructed types.
			if data.Class != asn1.ClassUniversal || data.Tag != asn1.TagOctetString {
				return nil, fmt.Errorf("bad data content (class: %d tag: %d)", data.Class, data.Tag)
			}

			dataValue = append(dataValue, data.Bytes...)
		}
	} else {
		dataValue = data.Bytes
	}

	return dataValue, nil
}

// Attribute ::= SEQUENCE {
//   attrType OBJECT IDENTIFIER,
//   attrValues SET OF AttributeValue }
//
// AttributeValue ::= ANY
type Attribute struct {
	Type asn1.ObjectIdentifier

	// This should be a SET OF ANY, but Go's asn1 parser can't handle slices of
	// RawValues. Use value() to get an AnySet of the value.
	RawValue asn1.RawValue
}

// NewAttribute creates a single-value Attribute.
func NewAttribute(typ asn1.ObjectIdentifier, val interface{}) (attr Attribute, err error) {
	var der []byte
	if der, err = asn1.Marshal(val); err != nil {
		return
	}

	var rv asn1.RawValue
	if _, err = asn1.Unmarshal(der, &rv); err != nil {
		return
	}

	if err = NewAnySet(rv).Encode(&attr.RawValue); err != nil {
		return
	}

	attr.Type = typ

	return
}

// Value further decodes the attribute Value as a SET OF ANY, which Go's asn1
// parser can't handle directly.
func (a Attribute) Value() (AnySet, error) {
	return DecodeAnySet(a.RawValue)
}

// Attributes is a common Go type for SignedAttributes and UnsignedAttributes.
//
// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
//
// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
type Attributes []Attribute

// MarshaledForSigning DER encodes the Attributes as needed for signing
// SignedAttributes. RFC5652 explains this encoding:
//   A separate encoding of the signedAttrs field is performed for message
//   digest calculation. The IMPLICIT [0] tag in the signedAttrs is not used for
//   the DER encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
//   encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0] tag,
//   MUST be included in the message digest calculation along with the length
//   and content octets of the SignedAttributes value.
func (attrs Attributes) MarshaledForSigning() ([]byte, error) {
	seq, err := asn1.Marshal(struct {
		Attributes `asn1:"set"`
	}{attrs})

	if err != nil {
		return nil, err
	}

	// unwrap the outer SEQUENCE
	var raw asn1.RawValue
	if _, err = asn1.Unmarshal(seq, &raw); err != nil {
		return nil, err
	}

	return raw.Bytes, nil
}

// GetOnlyAttributeValueBytes gets an attribute value, returning an error if the
// attribute occurs multiple times or has multiple values.
func (attrs Attributes) GetOnlyAttributeValueBytes(oid asn1.ObjectIdentifier) (rv asn1.RawValue, err error) {
	var vals []AnySet
	if vals, err = attrs.GetValues(oid); err != nil {
		return
	}
	if len(vals) != 1 {
		err = fmt.Errorf("expected 1 attribute found %d", len(vals))
		return
	}
	if len(vals[0].Elements) != 1 {
		err = fmt.Errorf("expected 1 attribute value found %d", len(vals[0].Elements))
		return
	}

	return vals[0].Elements[0], nil
}

// GetValues retreives the attributes with the given OID. A nil value is
// returned if the OPTIONAL SET of Attributes is missing from the SignerInfo. An
// empty slice is returned if the specified attribute isn't in the set.
func (attrs Attributes) GetValues(oid asn1.ObjectIdentifier) ([]AnySet, error) {
	if attrs == nil {
		return nil, nil
	}

	vals := []AnySet{}
	for _, attr := range attrs {
		if attr.Type.Equal(oid) {
			val, err := attr.Value()
			if err != nil {
				return nil, err
			}

			vals = append(vals, val)
		}
	}

	return vals, nil
}

// IssuerAndSerialNumber ::= SEQUENCE {
// 	issuer Name,
// 	serialNumber CertificateSerialNumber }
//
// CertificateSerialNumber ::= INTEGER
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// NewIssuerAndSerialNumber creates a IssuerAndSerialNumber SID for the given
// cert.
func NewIssuerAndSerialNumber(cert *x509.Certificate) (rv asn1.RawValue, err error) {
	sid := IssuerAndSerialNumber{
		SerialNumber: new(big.Int).Set(cert.SerialNumber),
	}

	if _, err = asn1.Unmarshal(cert.RawIssuer, &sid.Issuer); err != nil {
		return
	}

	var der []byte
	if der, err = asn1.Marshal(sid); err != nil {
		return
	}

	if _, err = asn1.Unmarshal(der, &rv); err != nil {
		return
	}

	return
}

// SignerInfo ::= SEQUENCE {
//   version CMSVersion,
//   sid SignerIdentifier,
//   digestAlgorithm DigestAlgorithmIdentifier,
//   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//   signatureAlgorithm SignatureAlgorithmIdentifier,
//   signature SignatureValue,
//   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
//
// CMSVersion ::= INTEGER
//               { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
//
// SignerIdentifier ::= CHOICE {
//   issuerAndSerialNumber IssuerAndSerialNumber,
//   subjectKeyIdentifier [0] SubjectKeyIdentifier }
//
// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
//
// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
//
// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
//
// SignatureValue ::= OCTET STRING
//
// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
type SignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        Attributes `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      Attributes `asn1:"set,optional,tag:1"`
}

// FindCertificate finds this SignerInfo's certificate in a slice of
// certificates.
func (si SignerInfo) FindCertificate(certs []*x509.Certificate) (*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, errors.New("no certificates")
	}
	switch si.Version {
	case 1: // SID is issuer and serial number
		isn, err := si.issuerAndSerialNumberSID()
		if err != nil {
			return nil, err
		}

		for _, cert := range certs {
			if bytes.Equal(cert.RawIssuer, isn.Issuer.FullBytes) && isn.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return cert, nil
			}
		}
	case 3: // SID is SubjectKeyIdentifier
		ski, err := si.subjectKeyIdentifierSID()
		if err != nil {
			return nil, err
		}

		for _, cert := range certs {
			for _, ext := range cert.Extensions {
				if oidSubjectKeyIdentifier.Equal(ext.Id) {
					if bytes.Equal(ski, ext.Value) {
						return cert, nil
					}
				}
			}
		}
	default:
		return nil, errors.New("unknown SignerInfo version")
	}

	return nil, errors.New("no matching certificate")
}

// issuerAndSerialNumberSID gets the SID, assuming it is a issuerAndSerialNumber.
func (si SignerInfo) issuerAndSerialNumberSID() (isn IssuerAndSerialNumber, err error) {
	if si.SID.Class != asn1.ClassUniversal || si.SID.Tag != asn1.TagSequence {
		err = ErrWrongType
		return
	}

	var rest []byte
	if rest, err = asn1.Unmarshal(si.SID.FullBytes, &isn); err == nil && len(rest) > 0 {
		err = errors.New("unexpected trailing data")
	}

	return
}

// subjectKeyIdentifierSID gets the SID, assuming it is a subjectKeyIdentifier.
func (si SignerInfo) subjectKeyIdentifierSID() ([]byte, error) {
	if si.SID.Class != asn1.ClassContextSpecific || si.SID.Tag != 0 {
		return nil, ErrWrongType
	}

	return si.SID.Bytes, nil
}

// Hash gets the crypto.Hash associated with this SignerInfo's DigestAlgorithm.
// 0 is returned for unrecognized algorithms.
func (si SignerInfo) Hash() crypto.Hash {
	return digestAlgorithmToHash[si.DigestAlgorithm.Algorithm.String()]
}

// X509SignatureAlgorithm gets the x509.SignatureAlgorithm that should be used
// for verifying this SignerInfo's signature.
func (si SignerInfo) X509SignatureAlgorithm() x509.SignatureAlgorithm {
	var (
		sigOID    = si.SignatureAlgorithm.Algorithm.String()
		digestOID = si.DigestAlgorithm.Algorithm.String()
	)

	return signatureAlgorithms[sigOID][digestOID]
}

// GetContentTypeAttribute gets the signed ContentType attribute from the
// SignerInfo.
func (si SignerInfo) GetContentTypeAttribute() (asn1.ObjectIdentifier, error) {
	rv, err := si.SignedAttrs.GetOnlyAttributeValueBytes(oidAttributeContentType)
	if err != nil {
		return nil, err
	}

	var ct asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(rv.FullBytes, &ct); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("unexpected trailing data")
	}

	return ct, nil
}

// GetMessageDigestAttribute gets the signed MessageDigest attribute from the
// SignerInfo.
func (si SignerInfo) GetMessageDigestAttribute() ([]byte, error) {
	rv, err := si.SignedAttrs.GetOnlyAttributeValueBytes(oidAttributeMessageDigest)
	if err != nil {
		return nil, err
	}
	if rv.Class != asn1.ClassUniversal {
		return nil, fmt.Errorf("expected class %d, got %d", asn1.ClassUniversal, rv.Class)
	}
	if rv.Tag != asn1.TagOctetString {
		return nil, fmt.Errorf("expected tag %d, got %d", asn1.TagOctetString, rv.Tag)
	}

	return rv.Bytes, nil
}

// GetSigningTimeAttribute gets the signed SigningTime attribute from the
// SignerInfo.
func (si SignerInfo) GetSigningTimeAttribute() (time.Time, error) {
	var t time.Time

	rv, err := si.SignedAttrs.GetOnlyAttributeValueBytes(oidAttributeSigningTime)
	if err != nil {
		return t, err
	}
	if rv.Class != asn1.ClassUniversal {
		return t, fmt.Errorf("expected class %d, got %d", asn1.ClassUniversal, rv.Class)
	}
	if rv.Tag != asn1.TagUTCTime && rv.Tag != asn1.TagGeneralizedTime {
		return t, fmt.Errorf("expected tag %d or %d, got %d", asn1.TagUTCTime, asn1.TagGeneralizedTime, rv.Tag)
	}

	if rest, err := asn1.Unmarshal(rv.FullBytes, &t); err != nil {
		return t, err
	} else if len(rest) > 0 {
		return t, errors.New("unexpected trailing data")
	}

	return t, nil
}

// SignedData ::= SEQUENCE {
//   version CMSVersion,
//   digestAlgorithms DigestAlgorithmIdentifiers,
//   encapContentInfo EncapsulatedContentInfo,
//   certificates [0] IMPLICIT CertificateSet OPTIONAL,
//   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//   signerInfos SignerInfos }
//
// CMSVersion ::= INTEGER
//               { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
//
// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
//
// CertificateSet ::= SET OF CertificateChoices
//
// CertificateChoices ::= CHOICE {
//   certificate Certificate,
//   extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
//   v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
//   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
//   other [3] IMPLICIT OtherCertificateFormat }
//
// OtherCertificateFormat ::= SEQUENCE {
//   otherCertFormat OBJECT IDENTIFIER,
//   otherCert ANY DEFINED BY otherCertFormat }
//
// RevocationInfoChoices ::= SET OF RevocationInfoChoice
//
// RevocationInfoChoice ::= CHOICE {
//   crl CertificateList,
//   other [1] IMPLICIT OtherRevocationInfoFormat }
//
// OtherRevocationInfoFormat ::= SEQUENCE {
//   otherRevInfoFormat OBJECT IDENTIFIER,
//   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
//
// SignerInfos ::= SET OF SignerInfo
type SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,set,tag:0"`
	CRLs             []asn1.RawValue `asn1:"optional,set,tag:1"`
	SignerInfos      []SignerInfo    `asn1:"set"`
}

// NewSignedData creates a new SignedData.
func NewSignedData(data []byte) (*SignedData, error) {
	eci, err := NewDataEncapsulatedContentInfo(data)
	if err != nil {
		return nil, err
	}

	return &SignedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{},
		EncapContentInfo: eci,
		SignerInfos:      []SignerInfo{},
	}, nil
}

// AddSignerInfo adds a SignerInfo to the SignedData.
func (sd *SignedData) AddSignerInfo(chain []*x509.Certificate, signer crypto.Signer) error {
	// figure out which certificate is associated with signer.
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}

	var cert *x509.Certificate
	for _, c := range chain {
		if err := sd.addCertificate(c); err != nil {
			return err
		}

		certPub, err := x509.MarshalPKIXPublicKey(c.PublicKey)
		if err != nil {
			return err
		}

		if bytes.Equal(pub, certPub) {
			cert = c
		}
	}
	if cert == nil {
		return errors.New("No certificate matching signer's public key")
	}

	sid, err := NewIssuerAndSerialNumber(cert)
	if err != nil {
		return err
	}

	digestAlgorithm := signatureAlgorithmToDigestAlgorithm[cert.SignatureAlgorithm]
	if digestAlgorithm == nil {
		return errors.New("unsupported digest algorithm")
	}

	signatureAlgorithm := signatureAlgorithmToSignatureAlgorithm[cert.SignatureAlgorithm]
	if signatureAlgorithm == nil {
		return errors.New("unsupported signature algorithm")
	}

	si := SignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digestAlgorithm},
		SignedAttrs:        nil,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureAlgorithm},
		Signature:          nil,
		UnsignedAttrs:      nil,
	}

	// Get the message
	data, err := sd.EncapContentInfo.DataEContent()
	if err != nil {
		return err
	}
	if data == nil {
		return errors.New("already detached")
	}

	// Digest the message.
	hash := si.Hash()
	if hash == 0 {
		return fmt.Errorf("unknown digest algorithm: %s", digestAlgorithm.String())
	}
	if !hash.Available() {
		return fmt.Errorf("Hash not avaialbe: %s", digestAlgorithm.String())
	}
	md := hash.New()
	if _, err = md.Write(data); err != nil {
		return err
	}

	// Build our SignedAttributes
	mdAttr, err := NewAttribute(oidAttributeMessageDigest, md.Sum(nil))
	if err != nil {
		return err
	}
	ctAttr, err := NewAttribute(oidAttributeContentType, oidData)
	if err != nil {
		return err
	}
	si.SignedAttrs = append(si.SignedAttrs, mdAttr, ctAttr)

	// Signature is over the marshaled signed attributes
	sm, err := si.SignedAttrs.MarshaledForSigning()
	if err != nil {
		return err
	}
	smd := hash.New()
	if _, errr := smd.Write(sm); errr != nil {
		return errr
	}
	if si.Signature, err = signer.Sign(rand.Reader, smd.Sum(nil), hash); err != nil {
		return err
	}

	sd.addDigestAlgorithm(si.DigestAlgorithm)

	sd.SignerInfos = append(sd.SignerInfos, si)

	return nil
}

// addCertificate adds a *x509.Certificate.
func (sd *SignedData) addCertificate(cert *x509.Certificate) error {
	for _, existing := range sd.Certificates {
		if bytes.Equal(existing.Bytes, cert.Raw) {
			return errors.New("certificate already added")
		}
	}

	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(cert.Raw, &rv); err != nil {
		return err
	}

	sd.Certificates = append(sd.Certificates, rv)

	return nil
}

// addDigestAlgorithm adds a new AlgorithmIdentifier if it doesn't exist yet.
func (sd *SignedData) addDigestAlgorithm(algo pkix.AlgorithmIdentifier) {
	for _, existing := range sd.DigestAlgorithms {
		if existing.Algorithm.Equal(algo.Algorithm) {
			return
		}
	}

	sd.DigestAlgorithms = append(sd.DigestAlgorithms, algo)
}

// X509Certificates gets the certificates, assuming that they're X.509 encoded.
func (sd *SignedData) X509Certificates() ([]*x509.Certificate, error) {
	// Certificates field is optional. Handle missing value.
	if sd.Certificates == nil {
		return nil, nil
	}

	// Empty set
	if len(sd.Certificates) == 0 {
		return []*x509.Certificate{}, nil
	}

	certs := make([]*x509.Certificate, 0, len(sd.Certificates))
	for _, raw := range sd.Certificates {
		if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
			return nil, fmt.Errorf("Unsupported certificate type (class %d, tag %d)", raw.Class, raw.Tag)
		}

		x509, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, x509)
	}

	return certs, nil
}

// ContentInfoDER returns the SignedData wrapped in a ContentInfo packet and DER
// encoded.
func (sd *SignedData) ContentInfoDER() ([]byte, error) {
	der, err := asn1.Marshal(*sd)
	if err != nil {
		return nil, err
	}

	ci := ContentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      der,
			IsCompound: true,
		},
	}

	return asn1.Marshal(ci)
}
