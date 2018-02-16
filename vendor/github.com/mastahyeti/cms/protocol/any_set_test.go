package protocol

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"testing"
)

func TestAnySet(t *testing.T) {
	// OpenSSL::ASN1::Set.new([
	//   OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(5)),
	//   OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(6))
	// ])
	der := []byte{49, 6, 2, 1, 5, 2, 1, 6}

	var rv asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &rv); err != nil {
		t.Fatal(err)
	} else if len(rest) > 0 {
		t.Fatal("trailing data")
	}

	as, err := DecodeAnySet(rv)
	if err != nil {
		t.Fatal(err)
	}

	if len(as.Elements) != 2 {
		t.Fatal("bad decoded values")
	}

	var i int
	if rest, err := asn1.Unmarshal(as.Elements[0].FullBytes, &i); err != nil {
		t.Fatal(err)
	} else if len(rest) > 0 {
		t.Fatal("trailing data")
	}
	if i != 5 {
		t.Fatalf("bad decoded value: %d", i)
	}

	if rest, err := asn1.Unmarshal(as.Elements[1].FullBytes, &i); err != nil {
		t.Fatal(err)
	} else if len(rest) > 0 {
		t.Fatal("trailing data")
	}
	if i != 6 {
		t.Fatalf("bad decoded value: %d", i)
	}

	var rv2 asn1.RawValue
	if err := as.Encode(&rv2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rv.FullBytes, rv2.FullBytes) {
		t.Fatal(hex.EncodeToString(rv2.FullBytes), " != ", hex.EncodeToString(rv.FullBytes))
	}
}
