package fakeca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"
)

func TestDefaults(t *testing.T) {
	assertNoPanic(t, func() {
		root := New(IsCA)

		if err := root.Certificate.CheckSignatureFrom(root.Certificate); err != nil {
			t.Fatal(err)
		}
	})
}

func TestIntermediate(t *testing.T) {
	assertNoPanic(t, func() {
		New().Issue()
	})
}

func TestSubject(t *testing.T) {
	assertNoPanic(t, func() {
		var (
			expected = "foobar"
			root     = New(Subject(pkix.Name{CommonName: expected}))
			actual   = root.Certificate.Subject.CommonName
		)

		if actual != expected {
			t.Fatalf("bad subject. expected '%s', got '%s'", expected, actual)
		}
	})
}

func TestNextSerialNumber(t *testing.T) {
	assertNoPanic(t, func() {
		var (
			expected = int64(123)
			ca       = New(NextSerialNumber(expected)).Issue()
			actual   = ca.Certificate.SerialNumber.Int64()
		)

		if actual != expected {
			t.Fatalf("bad sn. expected '%d', got '%d'", expected, actual)
		}
	})
}

func TestPrivateKey(t *testing.T) {
	assertNoPanic(t, func() {
		var (
			expected, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			ca          = New(PrivateKey(expected))
			actual      = ca.PrivateKey.(*ecdsa.PrivateKey)
		)

		if actual.D.Cmp(expected.D) != 0 {
			t.Fatalf("bad D. expected '%s', got '%s'", expected.D.String(), actual.D.String())
		}

		if actual.X.Cmp(expected.X) != 0 {
			t.Fatalf("bad X. expected '%s', got '%s'", expected.X.String(), actual.X.String())
		}

		if actual.Y.Cmp(expected.Y) != 0 {
			t.Fatalf("bad Y. expected '%s', got '%s'", expected.Y.String(), actual.Y.String())
		}
	})
}

func TestIssuer(t *testing.T) {
	assertNoPanic(t, func() {
		var (
			root  = New(IsCA)
			inter = New(Issuer(root))

			expected = root.Certificate.RawSubject
			actual   = inter.Certificate.RawIssuer
		)

		if !bytes.Equal(actual, expected) {
			t.Fatalf("bad issuer. expected '%s', got '%s'", string(expected), string(actual))
		}

		if err := inter.Certificate.CheckSignatureFrom(root.Certificate); err != nil {
			t.Fatal(err)
		}
	})
}

func TestIsCA(t *testing.T) {
	var (
		normal = New()
		ca     = New(IsCA)
	)

	if normal.Certificate.IsCA {
		t.Fatal("expected normal cert not to be CA")
	}

	if !ca.Certificate.IsCA {
		t.Fatal("expected CA cert to be CA")
	}
}

func TestChain(t *testing.T) {
	var (
		ca    = New(IsCA)
		inter = ca.Issue(IsCA)
		leaf  = inter.Issue()
	)

	if !leaf.Chain()[0].Equal(leaf.Certificate) {
		t.Fatal()
	}

	if !leaf.Chain()[1].Equal(inter.Certificate) {
		t.Fatal()
	}

	if !leaf.Chain()[2].Equal(ca.Certificate) {
		t.Fatal()
	}
}

func TestChainPool(t *testing.T) {
	var (
		ca    = New(IsCA)
		inter = ca.Issue(IsCA)
		leaf  = inter.Issue()
	)

	_, err := leaf.Certificate.Verify(x509.VerifyOptions{
		Roots:         ca.ChainPool(),
		Intermediates: leaf.ChainPool(),
	})

	if err != nil {
		t.Fatal(err)
	}
}

func TestPFX(t *testing.T) {
	assertNoPanic(t, func() {
		New().PFX("asdf")
	})
}

func TestAIA(t *testing.T) {
	i := New(IssuingCertificateURL("a", "b"), OCSPServer("c", "d"))

	if !reflect.DeepEqual(i.Certificate.IssuingCertificateURL, []string{"a", "b"}) {
		t.Error("bad IssuingCertificateURL: ", i.Certificate.IssuingCertificateURL)
	}

	if !reflect.DeepEqual(i.Certificate.OCSPServer, []string{"c", "d"}) {
		t.Error("bad OCSPServer: ", i.Certificate.OCSPServer)
	}
}

func assertNoPanic(t *testing.T, cb func()) {
	// Check that t.Helper() is defined for Go<1.9
	if h, ok := interface{}(t).(interface{ Helper() }); ok {
		h.Helper()
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatal(r)
		}
	}()

	cb()
}

func TestKeyUsage(t *testing.T) {
	root := New(IsCA, KeyUsage(x509.KeyUsageCertSign))
	if root.Certificate.KeyUsage != x509.KeyUsageCertSign {
		t.Fatalf("expected %x, got %d", x509.KeyUsageCertSign, root.Certificate.KeyUsage)
	}

	leaf := root.Issue(KeyUsage(x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature))
	if leaf.Certificate.KeyUsage != x509.KeyUsageDataEncipherment|x509.KeyUsageDigitalSignature {
		t.Fatalf("expected %x, got %d", x509.KeyUsageDataEncipherment|x509.KeyUsageDigitalSignature, leaf.Certificate.KeyUsage)
	}
}
