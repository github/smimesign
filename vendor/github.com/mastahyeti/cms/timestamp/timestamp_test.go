package timestamp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mastahyeti/cms/protocol"
)

var (
	errFakeClient = errors.New("fake client")
	lastRequest   *http.Request
)

type testHTTPClient struct{}

func (c testHTTPClient) Do(req *http.Request) (*http.Response, error) {
	lastRequest = req
	return nil, errFakeClient
}

func TestRequestDo(t *testing.T) {
	DefaultHTTPClient = testHTTPClient{}

	var (
		req = Request{Version: 1}
		err error
	)

	req.CertReq = true
	req.Nonce = GenerateNonce()
	if req.MessageImprint, err = NewMessageImprint(crypto.SHA256, bytes.NewReader([]byte("hello"))); err != nil {
		t.Fatal(err)
	}

	if _, err = req.Do("https://google.com"); err != errFakeClient {
		t.Fatalf("expected errFakeClient, got %v", err)
	}

	if lastRequest == nil {
		t.Fatal("expected lastRequest")
	}

	if ct := lastRequest.Header.Get("Content-Type"); ct != contentTypeTSQuery {
		t.Fatalf("expected ts content-type, got %s", ct)
	}

	body, err := lastRequest.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, body); err != nil {
		t.Fatal(err)
	}

	var req2 Request
	if rest, err := asn1.Unmarshal(buf.Bytes(), &req2); err != nil {
		t.Fatal(err)
	} else if len(rest) > 0 {
		t.Fatal("unexpected trailing data")
	}
}

func TestRequestMatches(t *testing.T) {
	var err error

	req := Request{Version: 1}
	req.Nonce = GenerateNonce()
	if req.MessageImprint, err = NewMessageImprint(crypto.SHA256, bytes.NewReader([]byte("hello"))); err != nil {
		t.Fatal(err)
	}

	tsti := Info{
		MessageImprint: req.MessageImprint,
		Nonce:          new(big.Int).Set(req.Nonce),
	}

	if !req.Matches(tsti) {
		t.Fatal("req doesn't match tsti")
	}

	tsti.Nonce.SetInt64(123)
	if req.Matches(tsti) {
		t.Fatal("req matches tsti")
	}
	tsti.Nonce.Set(req.Nonce)

	tsti.MessageImprint, _ = NewMessageImprint(crypto.SHA256, bytes.NewReader([]byte("asdf")))
	if req.Matches(tsti) {
		t.Fatal("req matches tsti")
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce := GenerateNonce()
	if nonce == nil {
		t.Fatal("expected non-nil nonce")
	}

	// don't check for exact bitlength match, since leading 0's don't count
	// towards length.
	if nonce.BitLen() < nonceBytes*8/2 {
		t.Fatalf("expected %d bit nonce, got %d", nonceBytes*8, nonce.BitLen())
	}
	if nonce.Cmp(new(big.Int)) == 0 {
		t.Fatal("expected non-zero nonce")
	}
}

func TestMessageImprint(t *testing.T) {
	m := []byte("hello, world!")
	mi1, err := NewMessageImprint(crypto.SHA256, bytes.NewReader(m))
	if err != nil {
		panic(err)
	}

	// same
	mi2, err := NewMessageImprint(crypto.SHA256, bytes.NewReader(m))
	if err != nil {
		panic(err)
	}
	if !mi1.Equal(mi2) {
		t.Fatal("expected m1==m2")
	}

	// round trip
	der, err := asn1.Marshal(mi1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = asn1.Unmarshal(der, &mi2); err != nil {
		t.Fatal(err)
	}
	if !mi1.Equal(mi2) {
		t.Fatal("expected m1==m2")
	}

	// null value for hash alrogithm parameters (as opposed to being absent entirely)
	mi2, _ = NewMessageImprint(crypto.SHA256, bytes.NewReader(m))
	mi2.HashAlgorithm.Parameters = asn1.NullRawValue
	if !mi1.Equal(mi2) {
		t.Fatal("expected m1==m2")
	}

	// different digest
	mi2, err = NewMessageImprint(crypto.SHA1, bytes.NewReader(m))
	if err != nil {
		panic(err)
	}
	if mi1.Equal(mi2) {
		t.Fatal("expected m1!=m2")
	}

	// different message
	mi2, err = NewMessageImprint(crypto.SHA256, bytes.NewReader([]byte("wrong")))
	if err != nil {
		panic(err)
	}
	if mi1.Equal(mi2) {
		t.Fatal("expected m1!=m2")
	}

	// bad digest
	mi2, _ = NewMessageImprint(crypto.SHA256, bytes.NewReader(m))
	mi2.HashedMessage = mi2.HashedMessage[0 : len(mi2.HashedMessage)-1]
	if mi1.Equal(mi2) {
		t.Fatal("expected m1!=m2")
	}
}

func TestErrorResponse(t *testing.T) {
	// Error response from request with missing message digest.
	respDER, _ := protocol.BER2DER(mustBase64Decode("MDQwMgIBAjApDCd0aGUgZGF0YSBzdWJtaXR0ZWQgaGFzIHRoZSB3cm9uZyBmb3JtYXQDAgIE"))
	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	rt, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(respDER, rt) {
		t.Fatal("expected round-tripping error TimeStampResp to equal")
	}

	expectedStatus := 2
	if resp.Status.Status != expectedStatus {
		t.Fatalf("expected status %d, got %d", expectedStatus, resp.Status.Status)
	}

	if numStrings := len(resp.Status.StatusString); numStrings != 1 {
		t.Fatalf("expected single status string, got %d", numStrings)
	}

	expectedString := "the data submitted has the wrong format"
	actualStrings, err := resp.Status.StatusString.Strings()
	if err != nil {
		t.Fatal(err)
	}
	if actualStrings[0] != expectedString {
		t.Fatalf("expected status string %s, got %s", expectedString, actualStrings[0])
	}

	expectedFailInfoLen := 6
	if resp.Status.FailInfo.BitLength != expectedFailInfoLen {
		t.Fatalf("expected len(failinfo) %d, got %d", expectedFailInfoLen, resp.Status.FailInfo.BitLength)
	}

	expectedFailInfo := []int{0, 0, 0, 0, 0, 1}
	for i, v := range expectedFailInfo {
		if actual := resp.Status.FailInfo.At(i); actual != v {
			t.Fatalf("expected failinfo[%d] to be %d, got %d", i, v, actual)
		}
	}
}

func TestPKIFreeText(t *testing.T) {
	der := mustBase64Decode("MBUME0JhZCBtZXNzYWdlIGRpZ2VzdC4=")
	var ft PKIFreeText
	if _, err := asn1.Unmarshal(der, &ft); err != nil {
		t.Fatal(err)
	}

	rt, err := asn1.Marshal(ft)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, rt) {
		t.Fatal("expected round-tripped PKIFreeText to match")
	}

	ft = PKIFreeText{}.Append("Bad message digest.")
	if err != nil {
		t.Fatal(err)
	}
	rt, err = asn1.Marshal(ft)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, rt) {
		t.Fatal("expected newly made PKIFreeText to match original DER")
	}
}

func TestTSTInfo(t *testing.T) {
	resp, err := ParseResponse(fixtureTimestampSymantecWithCerts)
	if err != nil {
		t.Fatal(err)
	}

	sd, err := resp.TimeStampToken.SignedDataContent()
	if err != nil {
		t.Fatal(err)
	}

	inf, err := ParseInfo(sd.EncapContentInfo)
	if err != nil {
		t.Fatal(err)
	}

	expectedVersion := 1
	if inf.Version != expectedVersion {
		t.Fatalf("expected version %d, got %d", expectedVersion, inf.Version)
	}

	expectedPolicy := asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 23, 3}
	if !inf.Policy.Equal(expectedPolicy) {
		t.Fatalf("expected policy %s, got %s", expectedPolicy.String(), inf.Policy.String())
	}

	expectedHash := crypto.SHA256
	if hash, err := inf.MessageImprint.Hash(); err != nil {
		t.Fatal(err)
	} else if hash != expectedHash {
		t.Fatalf("expected hash %d, got %d", expectedHash, hash)
	}

	expectedMI, _ := NewMessageImprint(crypto.SHA256, bytes.NewReader([]byte("hello\n")))
	if !inf.MessageImprint.Equal(expectedMI) {
		t.Fatalf("expected hash %s, got %s",
			hex.EncodeToString(expectedMI.HashedMessage),
			hex.EncodeToString(inf.MessageImprint.HashedMessage))
	}

	expectedSN := new(big.Int).SetBytes([]byte{0x34, 0x99, 0xB7, 0x2E, 0xCE, 0x6F, 0xB6, 0x6B, 0x68, 0x2D, 0x35, 0x25, 0xC6, 0xE5, 0x6A, 0x07, 0x77, 0x3D, 0xC9, 0xD8})
	if inf.SerialNumber.Cmp(expectedSN) != 0 {
		t.Fatalf("expected SN %s, got %s", expectedSN.String(), inf.SerialNumber.String())
	}

	timeFmt := "2006-01-02 15:04:05 MST"
	expectedGenTime, _ := time.Parse(timeFmt, "2018-05-09 18:25:22 UTC")
	if !inf.GenTime.Equal(expectedGenTime) {
		t.Fatalf("expected gentime %s, got %s", expectedGenTime.String(), inf.GenTime.String())
	}

	expectedAccuracy := 30 * time.Second
	if accuracy := inf.Accuracy.Duration(); accuracy != expectedAccuracy {
		t.Fatalf("expected accurracy %s, got %s", expectedAccuracy.String(), accuracy.String())
	}

	expectedGenTimeMax := expectedGenTime.Add(expectedAccuracy)
	if inf.genTimeMax() != expectedGenTimeMax {
		t.Fatalf("expected gentimemax %s, got %s", expectedGenTimeMax.String(), inf.genTimeMax().String())
	}

	expectedGenTimeMin := expectedGenTime.Add(-expectedAccuracy)
	if inf.genTimeMin() != expectedGenTimeMin {
		t.Fatalf("expected gentimemax %s, got %s", expectedGenTimeMin.String(), inf.genTimeMin().String())
	}

	expectedOrdering := false
	if inf.Ordering != expectedOrdering {
		t.Fatalf("expected ordering %t, got %t", expectedOrdering, inf.Ordering)
	}

	if inf.Nonce != nil {
		t.Fatal("expected nil nonce")
	}

	// don't bother with TSA, since we don't want to mess with parsing GeneralNames.

	if inf.Extensions != nil {
		t.Fatal("expected nil extensions")
	}
}

func TestParseTimestampSymantec(t *testing.T) {
	testParseInfo(t, fixtureTimestampSymantec)
}

func TestParseTimestampSymantecWithCerts(t *testing.T) {
	testParseInfo(t, fixtureTimestampSymantecWithCerts)
}

func TestParseTimestampDigicert(t *testing.T) {
	testParseInfo(t, fixtureTimestampDigicert)
}

func TestParseTimestampComodo(t *testing.T) {
	testParseInfo(t, fixtureTimestampComodo)
}

func TestParseTimestampGlobalSign(t *testing.T) {
	testParseInfo(t, fixtureTimestampGlobalSign)
}

func testParseInfo(t *testing.T, ber []byte) {
	resp, err := ParseResponse(ber)
	if err != nil {
		t.Fatal(err)
	}
	if err = resp.Status.GetError(); err != nil {
		t.Fatal(err)
	}

	sd, err := resp.TimeStampToken.SignedDataContent()
	if err != nil {
		t.Fatal(err)
	}

	certs, err := sd.X509Certificates()
	if err != nil {
		t.Fatal(err)
	}

	inf, err := ParseInfo(sd.EncapContentInfo)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := inf.MessageImprint.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if hash != crypto.SHA256 {
		t.Fatalf("expected SHA256 hash, found %s", inf.MessageImprint.HashAlgorithm.Algorithm.String())
	}

	if inf.SerialNumber == nil {
		t.Fatal("expected non-nill SN")
	}
	if inf.SerialNumber.Cmp(big.NewInt(0)) <= 0 {
		t.Fatal("expected SN>0")
	}

	if inf.Version != 1 {
		t.Fatalf("expected tst v1, found %d", inf.Version)
	}

	for _, si := range sd.SignerInfos {
		if _, err = si.FindCertificate(certs); err != nil && len(certs) > 0 {
			t.Fatal(err)
		}

		if ct, errr := si.GetContentTypeAttribute(); errr != nil {
			t.Fatal(errr)
		} else {
			// signerInfo contentType attribute must match signedData
			// encapsulatedContentInfo content type.
			if !ct.Equal(sd.EncapContentInfo.EContentType) {
				t.Fatalf("expected %s content, got %s", sd.EncapContentInfo.EContentType.String(), ct.String())
			}
		}

		if md, errr := si.GetMessageDigestAttribute(); errr != nil {
			t.Fatal(errr)
		} else if len(md) == 0 {
			t.Fatal("nil/empty message digest attribute")
		}

		if algo := si.X509SignatureAlgorithm(); algo == x509.UnknownSignatureAlgorithm {
			t.Fatalf("unknown signature algorithm")
		}

		var nilTime time.Time
		if st, errr := si.GetSigningTimeAttribute(); errr != nil {
			t.Fatal(errr)
		} else if st == nilTime {
			t.Fatal("0 value signing time")
		}
	}

	// round trip resp
	der, err := protocol.BER2DER(ber)
	if err != nil {
		t.Fatal(err)
	}

	der2, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(der, der2) {
		t.Fatal("re-encoded contentInfo doesn't match original")
	}

	// round trip signedData
	der = resp.TimeStampToken.Content.Bytes

	der2, err = asn1.Marshal(*sd)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(der, der2) {
		t.Fatal("re-encoded signedData doesn't match original")
	}
}

var fixtureTimestampSymantec = mustBase64Decode("" +
	"MIIDnjADAgEAMIIDlQYJKoZIhvcNAQcCoIIDhjCCA4ICAQMxDTALBglghkgBZQMEAgEwggEOBgsqhkiG" +
	"9w0BCRABBKCB/gSB+zCB+AIBAQYLYIZIAYb4RQEHFwMwMTANBglghkgBZQMEAgEFAAQgWJG1tSLV3wht" +
	"D/CxEPvZ0hu0/HFjrzTQgoai6Eb2vgMCFHERZNISITpb8tPCqDQtcNGcWhhSGA8yMDE4MDUwOTE0NTQy" +
	"MlowAwIBHqCBhqSBgzCBgDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9u" +
	"MR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYg" +
	"VGltZVN0YW1waW5nIFNpZ25lciAtIEcyMYICWjCCAlYCAQEwgYswdzELMAkGA1UEBhMCVVMxHTAbBgNV" +
	"BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMSgw" +
	"JgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBAhBUWPKq10HWRLyEqXugllLmMAsG" +
	"CWCGSAFlAwQCAaCBpDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTE4" +
	"MDUwOTE0NTQyMlowLwYJKoZIhvcNAQkEMSIEIF/3JTU7CB+pzL3Mf+8BKgIRZQlDbovL5WzNhyeTSCn6" +
	"MDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIM96wXrQR+zV/cNoIgMbEtTvB4tvK0xea6Qfj/LPS61nMAsG" +
	"CSqGSIb3DQEBAQSCAQCRxSB9MLAzK4YnNoFqIK9i71b011Q4pcyF6FEffC3ihOHjdmaHf/rFCeuv4roh" +
	"yGxW9cRTshE8UohcghMEuSbkSyaFtVt37o31NC1IvW0vouJVQ0j0rg6nQjlsO9rMGW7cJOS2lVnREqk5" +
	"+WfBMKJVnuYSXrnUdxcjSG++4eBCEF5L1fdCVjm4s1hagEORimvUoKuStibW0lwE8rdOEBjusZjRPDV6" +
	"hudDhI+2SJPCAFhnNaDDT73y+Ux4x5cVdxHV+tME8kUrr6Hm/l6EyPxu/jwrV/EdJFVsJfkemdJz/ACa" +
	"EbbTXfP8KuOwEyUwbFbRCXqO+Z6Gg0RqpiAZWCSM",
)

var fixtureTimestampSymantecWithCerts = mustBase64Decode("" +
	"MIIOLTADAgEAMIIOJAYJKoZIhvcNAQcCoIIOFTCCDhECAQMxDTALBglghkgBZQMEAgEwggEOBgsqhkiG" +
	"9w0BCRABBKCB/gSB+zCB+AIBAQYLYIZIAYb4RQEHFwMwMTANBglghkgBZQMEAgEFAAQgWJG1tSLV3wht" +
	"D/CxEPvZ0hu0/HFjrzTQgoai6Eb2vgMCFDSZty7Ob7ZraC01Jcblagd3PcnYGA8yMDE4MDUwOTE4MjUy" +
	"MlowAwIBHqCBhqSBgzCBgDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9u" +
	"MR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYg" +
	"VGltZVN0YW1waW5nIFNpZ25lciAtIEczoIIKizCCBTgwggQgoAMCAQICEHsFsdRJaFFE98mJ0pwZnRIw" +
	"DQYJKoZIhvcNAQELBQAwgb0xCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjEfMB0G" +
	"A1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazE6MDgGA1UECxMxKGMpIDIwMDggVmVyaVNpZ24sIElu" +
	"Yy4gLSBGb3IgYXV0aG9yaXplZCB1c2Ugb25seTE4MDYGA1UEAxMvVmVyaVNpZ24gVW5pdmVyc2FsIFJv" +
	"b3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTYwMTEyMDAwMDAwWhcNMzEwMTExMjM1OTU5WjB3" +
	"MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFu" +
	"dGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0Ew" +
	"ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7WZ1ZVU+djHJdGoGi61XzsAGtPHGsMo8Fa4aa" +
	"JwAyl2pNyWQUSym7wtkpuS7sY7Phzz8LVpD4Yht+66YH4t5/Xm1AONSRBudBfHkcy8utG7/YlZHz8O5s" +
	"+K2WOS5/wSe4eDnFhKXt7a+Hjs6Nx23q0pi1Oh8eOZ3D9Jqo9IThxNF8ccYGKbQ/5IMNJsN7CD5N+Qq3" +
	"M0n/yjvU9bKbS+GImRr1wOkzFNbfx4Dbke7+vJJXcnf0zajM/gn1kze+lYhqxdz0sUvUzugJkV+1hHk1" +
	"inisGTKPI8EyQRtZDqk+scz51ivvt9jk1R1tETqS9pPJnONI7rtTDtQ2l4Z4xaE3AgMBAAGjggF3MIIB" +
	"czAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADBmBgNVHSAEXzBdMFsGC2CGSAGG+EUB" +
	"BxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0" +
	"dHBzOi8vZC5zeW1jYi5jb20vcnBhMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL3Mu" +
	"c3ltY2QuY29tMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9zLnN5bWNiLmNvbS91bml2ZXJzYWwtcm9v" +
	"dC5jcmwwEwYDVR0lBAwwCgYIKwYBBQUHAwgwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFt" +
	"cC0yMDQ4LTMwHQYDVR0OBBYEFK9j1sqjToVy4Ke8QfMpojh/gHViMB8GA1UdIwQYMBaAFLZ3+mlIR59T" +
	"EtXC6gcydgfRlwcZMA0GCSqGSIb3DQEBCwUAA4IBAQB16rAt1TQZXDJF/g7h1E+meMFv1+rd3E/zociB" +
	"iPenjxXmQCmt5l30otlWZIRxMCrdHmEXZiBWBpgZjV1x8viXvAn9HJFHyeLojQP7zJAv1gpsTjPs1rST" +
	"yEyQY0g5QCHE3dZuiZg8tZiX6KkGtwnJj1NXQZAv4R5NTtzKEHhsQm7wtsX4YVxS9U72a433Snq+8839" +
	"A9fZ9gOoD+NT9wp17MZ1LqpmhQSZt/gGV+HGDvbor9rsmxgfqrnjOgC/zoqUywHbnsc4uw9Sq9HjlANg" +
	"Ck2g/idtFDL8P5dA4b+ZidvkORS92uTTw+orWrOVWFUEfcea7CMDjYUq0v+uqWGBMIIFSzCCBDOgAwIB" +
	"AgIQe9Tlr7rMBz+hASMEIkFNEjANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMU" +
	"U3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNV" +
	"BAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMTcxMjIzMDAwMDAwWhcNMjkwMzIy" +
	"MjM1OTU5WjCBgDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYD" +
	"VQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYgVGltZVN0" +
	"YW1waW5nIFNpZ25lciAtIEczMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArw6Kqvjcv2l7" +
	"VBdxRwm9jTyB+HQVd2eQnP3eTgKeS3b25TY+ZdUkIG0w+d0dg+k/J0ozTm0WiuSNQI0iqr6nCxvSB7Y8" +
	"tRokKPgbclE9yAmIJgg6+fpDI3VHcAyzX1uPCB1ySFdlTa8CPED39N0yOJM/5Sym81kjy4DeE035EMmq" +
	"ChhsVWFX0fECLMS1q/JsI9KfDQ8ZbK2FYmn9ToXBilIxq1vYyXRS41dsIr9Vf2/KBqs/SrcidmXs7Dby" +
	"lpWBJiz9u5iqATjTryVAmwlT8ClXhVhe6oVIQSGH5d600yaye0BTWHmOUjEGTZQDRcTOPAPstwDyOiLF" +
	"tG/l77CKmwIDAQABo4IBxzCCAcMwDAYDVR0TAQH/BAIwADBmBgNVHSAEXzBdMFsGC2CGSAGG+EUBBxcD" +
	"MEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBz" +
	"Oi8vZC5zeW1jYi5jb20vcnBhMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly90cy1jcmwud3Muc3ltYW50" +
	"ZWMuY29tL3NoYTI1Ni10c3MtY2EuY3JsMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQE" +
	"AwIHgDB3BggrBgEFBQcBAQRrMGkwKgYIKwYBBQUHMAGGHmh0dHA6Ly90cy1vY3NwLndzLnN5bWFudGVj" +
	"LmNvbTA7BggrBgEFBQcwAoYvaHR0cDovL3RzLWFpYS53cy5zeW1hbnRlYy5jb20vc2hhMjU2LXRzcy1j" +
	"YS5jZXIwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0yMDQ4LTYwHQYDVR0OBBYEFKUT" +
	"AamfhcwbbhYeXzsxqnk2AHsdMB8GA1UdIwQYMBaAFK9j1sqjToVy4Ke8QfMpojh/gHViMA0GCSqGSIb3" +
	"DQEBCwUAA4IBAQBGnq/wuKJfoplIz6gnSyHNsrmmcnBjL+NVKXs5Rk7nfmUGWIu8V4qSDQjYELo2JPoK" +
	"e/s702K/SpQV5oLbilRt/yj+Z89xP+YzCdmiWRD0Hkr+Zcze1GvjUil1AEorpczLm+ipTfe0F1mSQcO3" +
	"P4bm9sB/RDxGXBda46Q71Wkm1SF94YBnfmKst04uFZrlnCOvWxHqcalB+Q15OKmhDc+0sdo+mnrHIsV0" +
	"zd9HCYbE/JElshuW6YUI6N3qdGBuYKVWeg3IRFjc5vlIFJ7lv94AvXexmBRyFCTfxxEsHwA/w0sUxmcc" +
	"zB4Go5BfXFSLPuMzW4IPxbeGAk5xn+lmRT92MYICWjCCAlYCAQEwgYswdzELMAkGA1UEBhMCVVMxHTAb" +
	"BgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3Jr" +
	"MSgwJgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBAhB71OWvuswHP6EBIwQiQU0S" +
	"MAsGCWCGSAFlAwQCAaCBpDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8X" +
	"DTE4MDUwOTE4MjUyMlowLwYJKoZIhvcNAQkEMSIEIF5EOTCml8PvDOxSGeQnbCv+jXprtZlEut7wcOx/" +
	"xjfvMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIMR0znYAfQI5Tg2l5N58FMaA+eKCATz+9lPvXbcf32H4" +
	"MAsGCSqGSIb3DQEBAQSCAQBD1SGuMSSNtmwg38x/1d8v+uvX/2aPIJQS//p5Q54Y8moIEeezRhG0tK3N" +
	"81tfKdLeYTVE6VL8D7ZaCpbKzNJeD6DQM4S87bzH88H5RQOb2JTCvBPF3C/ytcl7ylezx6xsFNtftbW3" +
	"IOXETaWLgIBpeL7jUZQDhgQ4Xb9HeFl4vA6Wk2kR88h+8Tv2ci0AI9hZgHhH9c/OwPvd8TKbhSjK9qXK" +
	"DjaJr0BeVuYHPSWxfsxWVCOjNIOg7moWpPLSYQpqM2gdg5ppjQWffWYC4rywmM6XsBKs+EKFb++4GSOc" +
	"wc6JJCugxm8Ba1a6nDAAAQYf/pQyBRRlh/qCHZ0rIoFq",
)

var fixtureTimestampDigicert = mustBase64Decode("" +
	"MIIOuTADAgEAMIIOsAYJKoZIhvcNAQcCoIIOoTCCDp0CAQMxDzANBglghkgBZQMEAgEFADB3BgsqhkiG" +
	"9w0BCRABBKBoBGYwZAIBAQYJYIZIAYb9bAcBMDEwDQYJYIZIAWUDBAIBBQAEIFiRtbUi1d8IbQ/wsRD7" +
	"2dIbtPxxY6800IKGouhG9r4DAhAvZIfDsFuq0GRqVn9Wu2I8GA8yMDE4MDUwOTE4NDgxOFqgggu7MIIG" +
	"gjCCBWqgAwIBAgIQCcD8RsgEQhO1WYuvKE9OQTANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJVUzEV" +
	"MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhE" +
	"aWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0YW1waW5nIENBMB4XDTE3MDEwNDAwMDAwMFoXDTI4" +
	"MDExODAwMDAwMFowTDELMAkGA1UEBhMCVVMxETAPBgNVBAoTCERpZ2lDZXJ0MSowKAYDVQQDEyFEaWdp" +
	"Q2VydCBTSEEyIFRpbWVzdGFtcCBSZXNwb25kZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB" +
	"AQCelZhqNDtzG6h+/Me+KWmJx2gmRl89jWJzh4GjoZzwt1skN1qS1PRZ13aJ5NzVJ/DVZrwK7rQrMWes" +
	"WMVKkVkrRR4JAdZks1nujWZN+yNezBANC4pn71KuoAiQwlL39ai1bpsse53ntT77eM0yUBi/QLVMjLtX" +
	"9KBPEUVsQkK55a/W3/SnfApolg/SXylXzvsdMv/0EaETIvsSy+/XU9Lrl8uirBsdnVghUYLCwt7qKz8s" +
	"IoTQQ+w7Oz9HxPZW3EU3mLRrdLVZr3hXacgPCQJ43dhTwZnbYMSd6q6v4H6GSlypWGGoXnSKAShock6n" +
	"hp21AlKHcGZI047vgSTM3NhlAgMBAAGjggM4MIIDNDAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIw" +
	"ADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCCAb8GA1UdIASCAbYwggGyMIIBoQYJYIZIAYb9bAcBMIIB" +
	"kjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCCAWQGCCsGAQUFBwICMIIB" +
	"Vh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUA" +
	"IABjAG8AbgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUA" +
	"IABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkA" +
	"bgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQA" +
	"IABsAGkAYQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUA" +
	"ZAAgAGgAZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjALBglghkgBhv1sAxUwHwYD" +
	"VR0jBBgwFoAU9LbhIB3+Ka7S5GGlsqIlssgXNW4wHQYDVR0OBBYEFOGnMkruASEofVTV8geSbrQHDz2H" +
	"MHEGA1UdHwRqMGgwMqAwoC6GLGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtdHMu" +
	"Y3JsMDKgMKAuhixodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLXRzLmNybDCBhQYI" +
	"KwYBBQUHAQEEeTB3MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTwYIKwYBBQUH" +
	"MAKGQ2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1cmVkSURUaW1lc3Rh" +
	"bXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggEBAB7wQYIyru3xtDUT3FDC1ZeuIiKdDg6vM9NM/Xy/" +
	"bwERp5RlIlzGIqHIiVJrmoxzXNlePzLeFmBMizb9MZkKvcGEt40d74kmEwVW80fNR1uthLI4r2ojtUXj" +
	"HogyRoDSt6aZIv3BeM/1i9gMjAUJ7kTmgNVtcMyfUx4n3SpI3tqTZa1uZaOZp8JADnPMWE+PRSjlvJyI" +
	"5ijOYF0tJV2Lcy6lDVtR2ppO/1AFiSja8ni70lh4jUSnrDoAkXhpiWQE012W3yq/+aVMLJP/5ordgqzx" +
	"0rOihprBVYlWakc/+tYzlUM1iQV4Wjpp2iK4BEPTb2g1NnoUPkXpmGSGDxMMJkowggUxMIIEGaADAgEC" +
	"AhAKoSXW1jIbfkHkBdo2l8IVMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE" +
	"aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFz" +
	"c3VyZWQgSUQgUm9vdCBDQTAeFw0xNjAxMDcxMjAwMDBaFw0zMTAxMDcxMjAwMDBaMHIxCzAJBgNVBAYT" +
	"AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNV" +
	"BAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEB" +
	"AQUAA4IBDwAwggEKAoIBAQC90DLuS82Pf92puoKZxTlUKFe2I0rEDgdFM1EQfdD5fU1ofue2oPSNs4jk" +
	"l79jIZCYvxO8V9PD4X4I1moUADj3Lh477sym9jJZ/l9lP+Cb6+NGRwYaVX4LJ37AovWg4N4iPw7/fpX7" +
	"86O6Ij4YrBHk8JkDbTuFfAnT7l3ImgtU46gJcWvgzyIQD3XPcXJOCq3fQDpct1HhoXkUxk0kIzBdvOw8" +
	"YGqsLwfM/fDqR9mIUF79Zm5WYScpiYRR5oLnRlD9lCosp+R1PrqYD4R/nzEU1q3V8mTLex4F0IQZchfx" +
	"FwbvPc3WTe8GQv2iUypPhR3EHTyvz9qsEPXdrKzpVv+TAgMBAAGjggHOMIIByjAdBgNVHQ4EFgQU9Lbh" +
	"IB3+Ka7S5GGlsqIlssgXNW4wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wEgYDVR0TAQH/" +
	"BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgweQYIKwYBBQUHAQEE" +
	"bTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6" +
	"Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6" +
	"MHgwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j" +
	"cmwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j" +
	"cmwwUAYDVR0gBEkwRzA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2lj" +
	"ZXJ0LmNvbS9DUFMwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4IBAQBxlRLpUYdWac3v3dp8qmN6" +
	"s3jPBjdAhO9LhL/KzwMC/cWnww4gQiyvd/MrHwwhWiq3BTQdaq6Z+CeiZr8JqmDfdqQ6kw/4stHYfBli" +
	"6F6CJR7Euhx7LCHi1lssFDVDBGiy23UC4HLHmNY8ZOUfSBAYX4k4YU1iRiSHY4yRUiyvKYnleB/WCxSl" +
	"gNcSR3CzddWThZN+tpJn+1Nhiaj1a5bA9FhpDXzIAbG5KHW3mWOFIoxhynmUfln8jA/jb7UBJrZspe6H" +
	"USHkWGCbugwtK22ixH67xCUrRwIIfEmuE7bhfEJCKMYYVs9BNLZmXbZ0e/VWMyIvIjayS6JKldj1po5S" +
	"MYICTTCCAkkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE" +
	"CxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVz" +
	"dGFtcGluZyBDQQIQCcD8RsgEQhO1WYuvKE9OQTANBglghkgBZQMEAgEFAKCBmDAaBgkqhkiG9w0BCQMx" +
	"DQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTE4MDUwOTE4NDgxOFowLwYJKoZIhvcNAQkEMSIE" +
	"IDpdtczqob9pSfKx5ZEHQZSSHM3P+8uGHy1rXmrK9iUjMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFEAB" +
	"kUdcmIkd66EEr0cJG1621MvLMA0GCSqGSIb3DQEBAQUABIIBAIlFY+12XT6zvj4/0LVL5//VunTmYTKg" +
	"Z6eSrafFT9zOvGbDzm/8XnDLrUQq9Y4kQpE+eKfHWJOBQQZ0ze0wftUml+iRsvqEVlax7G03SzHyPIYH" +
	"HzEH/IKRlryHR5LgzzeFqS6IdVg18FBLvrs2fvPJlsj0ZGmAbwn6ntHDromtnkwZV6Cir5gH+wSKuA+Z" +
	"3Qj5odgrTQ9gmbmNlFgwp4BwH/vFbBB1eIt7EUD1KfZzThfdFYHnyl8eRcE5p5+MxvyAC78fPzlSlJJP" +
	"OES5LDDTx/Qvhet0PjJv70Z7kKgMmAA0BMTRuTnGfiVfEoFm2bzoKmwprU38EPz+PVnrbUA=",
)

var fixtureTimestampComodo = mustBase64Decode("" +
	"MIIDuDADAgEAMIIDrwYJKoZIhvcNAQcCoIIDoDCCA5wCAQMxDzANBglghkgBZQMEAgEFADCCAQ8GCyqG" +
	"SIb3DQEJEAEEoIH/BIH8MIH5AgEBBgorBgEEAbIxAgEBMDEwDQYJYIZIAWUDBAIBBQAEIFiRtbUi1d8I" +
	"bQ/wsRD72dIbtPxxY6800IKGouhG9r4DAhUA4Fc3zQPRFgrg3c8/sksclhBco7QYDzIwMTgwNTA5MTg0" +
	"NzQyWqCBjKSBiTCBhjELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G" +
	"A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxLDAqBgNVBAMTI0NPTU9ETyBT" +
	"SEEtMjU2IFRpbWUgU3RhbXBpbmcgU2lnbmVyMYICcTCCAm0CAQEwgaowgZUxCzAJBgNVBAYTAlVTMQsw" +
	"CQYDVQQIEwJVVDEXMBUGA1UEBxMOU2FsdCBMYWtlIENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1Qg" +
	"TmV0d29yazEhMB8GA1UECxMYaHR0cDovL3d3dy51c2VydHJ1c3QuY29tMR0wGwYDVQQDExRVVE4tVVNF" +
	"UkZpcnN0LU9iamVjdAIQTrCHj8wkNTay2Mn3vzlVdzANBglghkgBZQMEAgEFAKCBmDAaBgkqhkiG9w0B" +
	"CQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTE4MDUwOTE4NDc0MlowKwYLKoZIhvcNAQkQ" +
	"AgwxHDAaMBgwFgQUNlJ9T6JqaPnrRZbx2Zq7LA6nbfowLwYJKoZIhvcNAQkEMSIEIJeVWgArDRySkAZc" +
	"F6na8PZrsUBoQs2jUzy94iOFYfM6MA0GCSqGSIb3DQEBAQUABIIBAKKV56NeTuFn4VdoNv15X0bUWG3p" +
	"JSMRVbp1CWktnraj7E5m3BUmFlb4Dwrf3IMmE4QJrGrzDUWtUmpnHR4VuGAUmyajEcmDICc2gpBBG+aV" +
	"0Ng/lXQ1xAotKkU7/4wNQY1nOBsquZykYRHWbzJaVxaq8VEc0nVZY2o1TVDgWtLF7BHAd96vw4iVuG3O" +
	"Pb8izdFMwQ0t/TMNq0FD0hEFQDSTvVkayeaficblGbhf/p1xuCxSMoFBmnfO56aRX01E3SDNAgo3/hFl" +
	"na2g8ESpdWHRMqG3+8ehvgMwljUnhj5+iYT1YF7Rm6KcV2TCIh6QyokN42ji4BMqTlBA7vzSx5A=",
)

var fixtureTimestampGlobalSign = mustBase64Decode("" +
	"MIIDoTADAgEAMIIDmAYJKoZIhvcNAQcCoIIDiTCCA4UCAQMxCzAJBgUrDgMCGgUAMIHdBgsqhkiG9w0B" +
	"CRABBKCBzQSByjCBxwIBAQYJKwYBBAGgMgICMDEwDQYJYIZIAWUDBAIBBQAEIFiRtbUi1d8IbQ/wsRD7" +
	"2dIbtPxxY6800IKGouhG9r4DAhRYZmxGjSg8ojY0mWZG3dUdVW0mAxgPMjAxODA1MDkxODQ2MjRaoF2k" +
	"WzBZMQswCQYDVQQGEwJTRzEfMB0GA1UEChMWR01PIEdsb2JhbFNpZ24gUHRlIEx0ZDEpMCcGA1UEAxMg" +
	"R2xvYmFsU2lnbiBUU0EgZm9yIFN0YW5kYXJkIC0gRzIxggKRMIICjQIBATBoMFIxCzAJBgNVBAYTAkJF" +
	"MRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFRpbWVzdGFtcGlu" +
	"ZyBDQSAtIEcyAhIRIbRVNR67GrJPl+8H/iqzC4owCQYFKw4DAhoFAKCB/zAaBgkqhkiG9w0BCQMxDQYL" +
	"KoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTE4MDUwOTE4NDYyNFowIwYJKoZIhvcNAQkEMRYEFOmL" +
	"BqSyLEaL7tN+hDwnk6fha6wfMIGdBgsqhkiG9w0BCRACDDGBjTCBijCBhzCBhAQUg/3hunb+9VKRtQ1o" +
	"YZBtqkW1jLUwbDBWpFQwUjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKDAm" +
	"BgNVBAMTH0dsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gRzICEhEhtFU1Hrsask+X7wf+KrMLijAN" +
	"BgkqhkiG9w0BAQEFAASCAQBhWhjTagaTyATim1IHw0tF0wb22rlj6qXki86lclB/2uxBC8/3uLVd259z" +
	"iz7aaTmxSj3ksMBq9A75beQW5Be9vK00B/mj/p1dLrtgCcYZtV4uhoBkBx0YbriumEnvQoQL1bI1EiXh" +
	"TDbdTrGs2wXn3Xzw/qwqc7w+IjW1BjqzLf6BB9jw2raxMuWBA3EGMwGTumRx5x6a7j2Jx/9Uhs+3ce+9" +
	"ZRDtiWAFCkTQVvNLrAuHLTFK6lLOqfucrru76adpJMlTJ+VRut0adpwviS1Cb2ifIX1iUHjtGssihk6v" +
	"/tt7Yo4J341G5pC4JDXXhJvxHImNew3l0BWM0LROEgLM",
)

func mustBase64Decode(b64 string) []byte {
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(b64))
	buf := new(bytes.Buffer)

	if _, err := io.Copy(buf, decoder); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

// The fixtures above are complete TimeStampResp's, but most of our tests only
// care about the TimeStampToken (CMS ContentInfo) part of it.
func mustExtractTimeStampToken(ber []byte) []byte {
	resp, err := ParseResponse(ber)
	if err != nil {
		panic(err)
	}

	tstDER, err := asn1.Marshal(resp.TimeStampToken)
	if err != nil {
		panic(err)
	}

	return tstDER
}
