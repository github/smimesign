package cms

import (
	"testing"
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
}
