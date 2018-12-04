package cms

import (
	"crypto/x509"
	"testing"
	"time"
)

var (
	examplePrivateKey = leaf.PrivateKey
	exampleChain      = leaf.Chain()
)

func TestSign(t *testing.T) {
	data := []byte("hello, world!")

	ci, err := Sign(data, leaf.Chain(), leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	sd2, err := ParseSignedData(ci)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = sd2.Verify(rootOpts); err != nil {
		t.Fatal(err)
	}

	// test that we're including whole chain in sd
	sdCerts, err := sd2.psd.X509Certificates()
	if err != nil {
		t.Fatal(err)
	}
	for _, chainCert := range leaf.Chain() {
		var found bool
		for _, sdCert := range sdCerts {
			if sdCert.Equal(chainCert) {
				if found == true {
					t.Fatal("duplicate cert in sd")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("missing cert in sd")
		}
	}

	// check that we're including signing time attribute
	st, err := sd2.psd.SignerInfos[0].GetSigningTimeAttribute()
	if st.After(time.Now().Add(time.Second)) || st.Before(time.Now().Add(-time.Second)) {
		t.Fatal("expected SigningTime to be now. Difference was", st.Sub(time.Now()))
	}
}

func TestSignDetached(t *testing.T) {
	data := []byte("hello, world!")

	ci, err := SignDetached(data, leaf.Chain(), leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	sd2, err := ParseSignedData(ci)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = sd2.VerifyDetached(data, rootOpts); err != nil {
		t.Fatal(err)
	}

	// test that we're including whole chain in sd
	sdCerts, err := sd2.psd.X509Certificates()
	if err != nil {
		t.Fatal(err)
	}
	for _, chainCert := range leaf.Chain() {
		var found bool
		for _, sdCert := range sdCerts {
			if sdCert.Equal(chainCert) {
				if found == true {
					t.Fatal("duplicate cert in sd")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("missing cert in sd")
		}
	}

	// check that we're including signing time attribute
	st, err := sd2.psd.SignerInfos[0].GetSigningTimeAttribute()
	if st.After(time.Now().Add(time.Second)) || st.Before(time.Now().Add(-time.Second)) {
		t.Fatal("expected SigningTime to be now. Difference was", st.Sub(time.Now()))
	}
}

func TestSignRemoveHeaders(t *testing.T) {
	sd, err := NewSignedData([]byte("hello, world"))
	if err != nil {
		t.Fatal(err)
	}
	if err = sd.Sign(leaf.Chain(), leaf.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err = sd.SetCertificates([]*x509.Certificate{}); err != nil {
		t.Fatal(err)
	}
	if certs, err := sd.GetCertificates(); err != nil {
		t.Fatal(err)
	} else if len(certs) != 0 {
		t.Fatal("expected 0 certs")
	}

	der, err := sd.ToDER()
	if err != nil {
		t.Fatal(err)
	}
	if sd, err = ParseSignedData(der); err != nil {
		t.Fatal(err)
	}
	sd.SetCertificates([]*x509.Certificate{leaf.Certificate})

	opts := x509.VerifyOptions{
		Roots:         root.ChainPool(),
		Intermediates: leaf.ChainPool(),
	}

	if _, err := sd.Verify(opts); err != nil {
		t.Fatal(err)
	}
}
