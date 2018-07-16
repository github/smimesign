package cms

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/mastahyeti/cms/protocol"
)

func verifyOptionsForSignedData(sd *SignedData) (opts x509.VerifyOptions) {
	certs, err := sd.psd.X509Certificates()
	if err != nil {
		panic(err)
	}

	// add self-signed cert as trusted root
	if len(certs) == 1 {
		opts.Roots = x509.NewCertPool()
		opts.Roots.AddCert(certs[0])
	}

	// trust signing time
	signingTime, err := sd.psd.SignerInfos[0].GetSigningTimeAttribute()
	if err != nil {
		panic(err)
	}

	opts.CurrentTime = signingTime

	return
}

func TestVerify(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureOne)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sd.Verify(verifyOptionsForSignedData(sd)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyGPGSMAttached(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureGPGSMAttached)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = sd.Verify(verifyOptionsForSignedData(sd)); err != nil {
		t.Fatal(err)
	}

	data, err := sd.GetData()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("hello\n")) {
		t.Fatal("bad msg")
	}
}

func TestVerifyGPGSMDetached(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureGPGSM)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sd.VerifyDetached([]byte("hello, world!\n"), verifyOptionsForSignedData(sd)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyGPGSMNoCerts(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureNoCertsGPGSM)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sd.VerifyDetached([]byte("hello, world!\n"), x509.VerifyOptions{}); err != protocol.ErrNoCertificate {
		t.Fatalf("expected %v, got %v", protocol.ErrNoCertificate, err)
	}
}

func TestVerifyOpenSSLAttached(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureOpenSSLAttached)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sd.Verify(verifyOptionsForSignedData(sd)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyOpenSSLDetached(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureOpenSSLDetached)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sd.VerifyDetached([]byte("hello, world!"), verifyOptionsForSignedData(sd)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyOutlookDetached(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureOutlookDetached)
	if err != nil {
		t.Fatal(err)
	}

	opts := x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}

	if _, err := sd.VerifyDetached(fixtureMessageOutlookDetached, opts); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyChain(t *testing.T) {
	signerChain := leaf.Chain()
	ber, _ := Sign([]byte("hi"), leaf.Chain(), leaf.PrivateKey)
	sd, _ := ParseSignedData(ber)

	// good root
	chains, err := sd.Verify(rootOpts)
	if err != nil {
		t.Fatal(err)
	}

	if len(chains) != 1 || len(chains[0]) != 1 || len(chains[0][0]) != len(signerChain) {
		t.Fatal("bad chain")
	}

	for i, c := range signerChain {
		if !chains[0][0][i].Equal(c) {
			t.Fatalf("bad cert: %d", i)
		}
	}

	// bad root
	if _, err = sd.Verify(otherRootOpts); err != nil {
		if _, isX509Err := err.(x509.UnknownAuthorityError); !isX509Err {
			t.Fatalf("expected x509.UnknownAuthorityError, got %v", err)
		}
	}

	// system root
	if _, err = sd.Verify(x509.VerifyOptions{}); err != nil {
		if _, isX509Err := err.(x509.UnknownAuthorityError); !isX509Err {
			t.Fatalf("expected x509.UnknownAuthorityError, got %v", err)
		}
	}

	// no root
	if _, err = sd.Verify(x509.VerifyOptions{Roots: x509.NewCertPool()}); err != nil {
		if _, isX509Err := err.(x509.UnknownAuthorityError); !isX509Err {
			t.Fatalf("expected x509.UnknownAuthorityError, got %v", err)
		}
	}
}

var fixtureSignatureOne = mustBase64Decode("" +
	"MIIDVgYJKoZIhvcNAQcCoIIDRzCCA0MCAQExCTAHBgUrDgMCGjAcBgkqhkiG9w0B" +
	"BwGgDwQNV2UgdGhlIFBlb3BsZaCCAdkwggHVMIIBQKADAgECAgRpuDctMAsGCSqG" +
	"SIb3DQEBCzApMRAwDgYDVQQKEwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3Rh" +
	"cmswHhcNMTUwNTA2MDQyNDQ4WhcNMTYwNTA2MDQyNDQ4WjAlMRAwDgYDVQQKEwdB" +
	"Y21lIENvMREwDwYDVQQDEwhKb24gU25vdzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw" +
	"gYkCgYEAqr+tTF4mZP5rMwlXp1y+crRtFpuLXF1zvBZiYMfIvAHwo1ta8E1IcyEP" +
	"J1jIiKMcwbzeo6kAmZzIJRCTezq9jwXUsKbQTvcfOH9HmjUmXBRWFXZYoQs/OaaF" +
	"a45deHmwEeMQkuSWEtYiVKKZXtJOtflKIT3MryJEDiiItMkdybUCAwEAAaMSMBAw" +
	"DgYDVR0PAQH/BAQDAgCgMAsGCSqGSIb3DQEBCwOBgQDK1EweZWRL+f7Z+J0kVzY8" +
	"zXptcBaV4Lf5wGZJLJVUgp33bpLNpT3yadS++XQJ+cvtW3wADQzBSTMduyOF8Zf+" +
	"L7TjjrQ2+F2HbNbKUhBQKudxTfv9dJHdKbD+ngCCdQJYkIy2YexsoNG0C8nQkggy" +
	"axZd/J69xDVx6pui3Sj8sDGCATYwggEyAgEBMDEwKTEQMA4GA1UEChMHQWNtZSBD" +
	"bzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrAgRpuDctMAcGBSsOAwIaoGEwGAYJKoZI" +
	"hvcNAQkDMQsGCSqGSIb3DQEHATAgBgkqhkiG9w0BCQUxExcRMTUwNTA2MDAyNDQ4" +
	"LTA0MDAwIwYJKoZIhvcNAQkEMRYEFG9D7gcTh9zfKiYNJ1lgB0yTh4sZMAsGCSqG" +
	"SIb3DQEBAQSBgFF3sGDU9PtXty/QMtpcFa35vvIOqmWQAIZt93XAskQOnBq4OloX" +
	"iL9Ct7t1m4pzjRm0o9nDkbaSLZe7HKASHdCqijroScGlI8M+alJ8drHSFv6ZIjnM" +
	"FIwIf0B2Lko6nh9/6mUXq7tbbIHa3Gd1JUVire/QFFtmgRXMbXYk8SIS",
)

var fixtureSignatureGPGSMAttached = mustBase64Decode("" +
	"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" +
	"SDXMwnexRO3w39tu4ChUFbsX8l5CAAAAAAAA",
)

var fixtureSignatureGPGSM = mustBase64Decode("" +
	"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" +
	"SX+du6QAAAAAAAA=",
)

var fixtureSignatureNoCertsGPGSM = mustBase64Decode("" +
	"MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0B" +
	"BwEAADGCAeEwggHdAgEBMCAwFDESMBAGA1UEAxMJQmVuIFRvZXdzAggWdNrn7G+u" +
	"SDANBglghkgBZQMEAgEFAKCBkzAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG" +
	"CSqGSIb3DQEJBTEPFw0xNzExMTcwMDQxNDhaMCgGCSqGSIb3DQEJDzEbMBkwCwYJ" +
	"YIZIAWUDBAECMAoGCCqGSIb3DQMHMC8GCSqGSIb3DQEJBDEiBCBNyg/V9CSjGwOr" +
	"gHy6536zK/LQie7RzuFUs6/tRY3g3DANBgkqhkiG9w0BAQEFAASCAQAvGAGPMaH3" +
	"oRiNDU0AGIVyjXUrZ8g2VRazGCTuuO0CPGWBDbBuuvCePuWTddcv5KHHyrYO0yUD" +
	"xergVhh1EXIsOItHbJ6QeMstmY8Ub7HGm4Srdtm3MMSEe24zRmKK5yvPfeaaXeb6" +
	"MASKXvViU/j9VDwUZ2CFPUzPq8DlS6j4w6dapfphFGN1wJV3ADLUzUkTXfXQ57HE" +
	"WUKdbxgcuyBH7eLhZpKAXP31iRKm2b7dV50SruRCqNYZOp8bUQ57bC2jels0dzQd" +
	"EQS76O/DH6eQ3/OgvpmR8BjlujA82tgjqP7fj0S7Cw2VlPqcey0iqRmAmiO2qzOI" +
	"KAYzMkxWr7iUAAAAAAAA",
)

var fixtureSignatureOpenSSLAttached = mustBase64Decode("" +
	"MIIFGgYJKoZIhvcNAQcCoIIFCzCCBQcCAQExDzANBglghkgBZQMEAgEFADAcBgkq" +
	"hkiG9w0BBwGgDwQNaGVsbG8sIHdvcmxkIaCCAqMwggKfMIIBh6ADAgECAgEAMA0G" +
	"CSqGSIb3DQEBBQUAMBMxETAPBgNVBAMMCGNtcy10ZXN0MB4XDTE3MTEyMDIwNTM0" +
	"M1oXDTI3MTExODIwNTM0M1owEzERMA8GA1UEAwwIY21zLXRlc3QwggEiMA0GCSqG" +
	"SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWMRnJdRQxw8j8Yn3jh/rcZyeALStl+MmM" +
	"TEtr6XsmMOWQhnP6nCAIOw5EIAXGpKl4Yg3F2gDKmJCVl279Q+G9nLtvmWvCzu19" +
	"BJUG7jVLWzO8KSuJa83iiilZUP2adVZujdGB6dxekIBu7vkYi9XxZJm4edhj0bkd" +
	"EtkxLCNUGDQKsywnKOTWzfefT9UCQJyLwt74ThJtNX7uoYrfAHNfBARk3Kx+wf4U" +
	"Grd2GmSe8Lnr3FNcZ/uMJffsYvBk3fbDwYsVC6rd4BuJvvri3K1dti3rnvDEnuMI" +
	"Ve7a2n7NE7yV0cietIjKeeY8bO25lwrTtBzgP5y1G9spjzAtiRLZAgMBAAEwDQYJ" +
	"KoZIhvcNAQEFBQADggEBAMkYPFmsHYlyO+KZMKEWUWOdw1rwrIVhLQOKqLz8Wbe8" +
	"lIQ5pdsd4S1DqvMEzYyMtpZckZ9mOBZh/SQsmdb8sZnQwiMvlPSO6IWp/MpuP+VK" +
	"v8IBAr1aaLlMaelV086uIFc9coE6XAdWFrGlUT9FYM00JwoSfi51vbcqbIh6P8y9" +
	"uwHqlt2vkVYujto+p0UMBnBZkfKBgzMG7ILWpJbVszmpesVzI2XUgq8BxlO0fvw5" +
	"m/R4bAtHqXTK0xVrTBXUg6izFbdA3pVlFMiuv8Kq2cyBg+VkXGYmZ37BGhApe5Le" +
	"Dabe4iGcXQMW4lunjRSv8gDu/ODA/20OMNVDOx92MTIxggIqMIICJgIBATAYMBMx" +
	"ETAPBgNVBAMMCGNtcy10ZXN0AgEAMA0GCWCGSAFlAwQCAQUAoIHkMBgGCSqGSIb3" +
	"DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE3MTEyMDIwNTM0M1ow" +
	"LwYJKoZIhvcNAQkEMSIEIGjmVrJR5n6DWL74SDqw1RxmGfPnoanw51g41B/zaPco" +
	"MHkGCSqGSIb3DQEJDzFsMGowCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQBFjALBglg" +
	"hkgBZQMEAQIwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMC" +
	"AgFAMAcGBSsOAwIHMA0GCCqGSIb3DQMCAgEoMA0GCSqGSIb3DQEBAQUABIIBAJHB" +
	"kfH1hZ4Y0TI6PdW7DNFnb++KQJiu4NmzE7SyTJOCxC2W44uAKUdJw7c8cdn/lcb/" +
	"y1kvwNbi2kysuZSTpywBIjHSTw3BTwdaNJFd6HUV1mX2IQRfaJIPW5fqkhLfQtZ6" +
	"LZka/HWQ5fwA51g6lVNTMbStjsPlBef6qEDcCLMp/4CNEqC5+fUx8Jb7Q5mvyCHQ" +
	"3IZrIEMLBYhrgrm61qh/MXKnAqlEo6XxN1fL0CXDxy9dYPSKr2G66o9+BjmYktF5" +
	"3MfxrT4JDizd2S/8BVEv+H+uHmrpyRxMceREPJVrVHOdd922hyKALbAGcoyMdXpj" +
	"ZdMtHnR5z07z9wxvwiw=",
)

var fixtureSignatureOpenSSLDetached = mustBase64Decode("" +
	"MIIFCQYJKoZIhvcNAQcCoIIE+jCCBPYCAQExDzANBglghkgBZQMEAgEFADALBgkq" +
	"hkiG9w0BBwGgggKjMIICnzCCAYegAwIBAgIBADANBgkqhkiG9w0BAQUFADATMREw" +
	"DwYDVQQDDAhjbXMtdGVzdDAeFw0xNzExMjAyMTE0NDdaFw0yNzExMTgyMTE0NDda" +
	"MBMxETAPBgNVBAMMCGNtcy10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB" +
	"CgKCAQEA5VQ0FRvQRA9F+6nss77yUcm3x8IOoJV/icQrtrkR/BHGgeepcLIcHkWh" +
	"s/cap69xR5TCtONy0I4tqKf/vXnKXvMjsGGrecFMi8NVTbEoNg9m47nbdO7BY1+f" +
	"waLfwAX5vf17BRSqA0wRIoNIzJc07mNrI84EbKfVmDtPrqzwnT0sIKqj5p2PQdWi" +
	"sPwOocLYJBdAPglnLuFk6WTZalJRgV7h50nl1GBDKJVo1Yc7zqPdqWzHzFqK759g" +
	"CHBZMYJdqIx/wev/l66oEcJZr6gnnKzq8lsWljpjVWD96z/W/fehWZsWlWkvmrus" +
	"qizMbL0vCx8HrReo7+hszMIHR5bwTwIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAD" +
	"ZjPxm/JHc4KoQUaVOSAU97lO60MD21Ud0LtaebbiSJnaMH9a/rb3kuxJAKVSBhDp" +
	"wyRK19KNtaSXHEAD48aJeT7J4wsDJFNfKGx/9R2iYB5xjc/POpK13A/o4fDrpLWL" +
	"1doIc0KjVA63BXaYOwsEj2iKzUKNFZ2kS3bXMkEBhUDUXtSo08WFI7UkgYTuIfM2" +
	"LS/wyORcwZIEIvq+ndkch/nAyQZ8U0/85dgwpOQcyZ0UDiu8Ti9z9IUlhxSq2T13" +
	"JhIfiMa4m27y71JmsFy12uN3fGBckkyNkKkxVMy0H4Ukr1hq/ZkvH3HdrEnWmNEu" +
	"WdU7WvIBsbe3U2idyhBSMYICKjCCAiYCAQEwGDATMREwDwYDVQQDDAhjbXMtdGVz" +
	"dAIBADANBglghkgBZQMEAgEFAKCB5DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB" +
	"MBwGCSqGSIb3DQEJBTEPFw0xNzExMjAyMTE0NDdaMC8GCSqGSIb3DQEJBDEiBCBo" +
	"5layUeZ+g1i++Eg6sNUcZhnz56Gp8OdYONQf82j3KDB5BgkqhkiG9w0BCQ8xbDBq" +
	"MAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3" +
	"DQMHMA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggq" +
	"hkiG9w0DAgIBKDANBgkqhkiG9w0BAQEFAASCAQAcLsBbjvlhz+HAy7m5cvh8tRav" +
	"xT05fFK1hwBC287z+D/UaCrvrd2vR4bdUV8jfS5iTyUfX/BikOljxRwUMgtBLPKq" +
	"gdNokoxUoQiqVOdgCER0isNLF/8+O29reI6N/9Mp+IpfE41o2xcRrggfncuPX00K" +
	"MB2K4/ZF35HddfblHIgQ+9gWfHE52KMur4XeI5sc/izMNuPyR8VVB7St5JLMepHj" +
	"UtbPYBJ0bRSwDX1JAoB+Ze/mPvCmo/pS5QyYfNvXg3Jw4TVoud5+oUH9r6MwSxzN" +
	"BSws5SM9d0GAafR+Hj19x9s8ypUjLJmGIAjeTrlgcYUTJjnfEtZBL5Je2FuK",
)

var fixtureSignatureOutlookDetached = mustBase64Decode("" +
	"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" +
	"MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDBDBgNVHSAEPDA6MDgGCmCGSAGG/WwEAQIw" +
	"KjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBiAYDVR0fBIGAMH4w" +
	"PaA7oDmGN2h0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1cmVkSURDQS1n" +
	"Mi5jcmwwPaA7oDmGN2h0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1cmVk" +
	"SURDQS1nMi5jcmwweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp" +
	"Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy" +
	"dFNIQTJBc3N1cmVkSURDQS5jcnQwDQYJKoZIhvcNAQELBQADggEBADh2DYGfn+1eg21dTa34iZlu" +
	"IyActG/S23bCLnJSThPbiCfZgGkKr9Bq6TSJ4qQfsquIB7cO46mJ+tzHL570xAsJ4pC7z3RhBdzK" +
	"j9uT6ZUExdHQs2FoPjU5uT1UhqHv7T9qYp689XpZ2xPLH59SwLASIVnoQFIS0MKT8AN6ZgKxDWDY" +
	"EUyRfGQxxDbfqWhncH0qxT20mv8TnvIMo2ngsCBZfpJcv9u3LijnD7uVCZ2qRIJkmJ7s1eoGc05c" +
	"Z+7NeA8vC28BgGe2svMUlRInaNsMDUBmizI4x6DnS8uVlX22KAdPML9NvPOfCGCohDevZgCSMx/o" +
	"nH+foA+rOCngkR8wggZOMIIFNqADAgECAhAErnlgZmaQGrnFf6ZsW9zNMA0GCSqGSIb3DQEBCwUA" +
	"MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp" +
	"Y2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xMzExMDUx" +
	"MjAwMDBaFw0yODExMDUxMjAwMDBaMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ" +
	"bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IFNIQTIgQXNz" +
	"dXJlZCBJRCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANz4ESM/arXvwCd5Gy0F" +
	"h6IQQzHfDtQVG093pCLOPoxw8L4Hjt0nKrwBHbYsCsrdaVgfQe1qBR/aY3hZHiIsK/i6fsk1O1bx" +
	"H3xCfiWwIxnGRTjXPUT5IHxgrhywWhgEvo8796nwlJqmDGNJtkEXU0AyvU/mUHpQHyVF6PGJr83/" +
	"Xv9Q8/AXEf+9xYn1vWK52PuORQSFbZnNxUhN/SarAjZF6jbXX2riGoJBCtzp2fWRF47GIa04PBPm" +
	"Hn9mnNVN2Uba9s9Sp307JMO0wVE1xpvr1O9+5HsD4US9egs34E/LgooNcRjkpuCJLBvzsnM8wbCS" +
	"nhh9vat9xX0IoSzCn3MCAwEAAaOCAvgwggL0MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/" +
	"BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu" +
	"Y29tMIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRB" +
	"c3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl" +
	"cnRBc3N1cmVkSURSb290Q0EuY3JsMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDCCAbMG" +
	"A1UdIASCAaowggGmMIIBogYKYIZIAYb9bAACBDCCAZIwKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3" +
	"LmRpZ2ljZXJ0LmNvbS9DUFMwggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABv" +
	"AGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQA" +
	"ZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0" +
	"ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQA" +
	"eQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBp" +
	"AGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUA" +
	"cgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wHQYDVR0OBBYEFOcCI4AAT9jXvJQL" +
	"2T90OUkyPIp5MB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBCwUA" +
	"A4IBAQBO1Iknuf0dh3d+DygFkPEKL8k7Pr2TnJDGr/qRUYcyVGvoysFxUVyZjrX64GIZmaYHmnwT" +
	"J9vlAqKEEtkV9gpEV8Q0j21zHzrWoAE93uOC5EVrsusl/YBeHTmQvltC9s6RYOP5oFYMSBDOM2h7" +
	"zZOr8GrLT1gPuXtdGwSBnqci4ldJJ+6Skwi+aQhTAjouXcgZ9FCATgLZsF2RtJOH+ZaWgVVAjmbt" +
	"gti7KF/tTGHtBlgoGVMRRLxHICmyBGzYiVSZO3XbZ3gsHpJ4xlU9WBIRMm69QwxNNNt7xkLb7L6r" +
	"m2FMBpLjjt8hKlBXBMBgojXVJJ5mNwlJz9X4ZbPg4m7CMYIDvzCCA7sCAQEweTBlMQswCQYDVQQG" +
	"EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQw" +
	"IgYDVQQDExtEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ0ECEAWkzvCWLw1xJSpSGJSTKHAwDQYJ" +
	"YIZIAWUDBAIBBQCgggIXMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8X" +
	"DTE3MTEyOTE0NDMxOVowLwYJKoZIhvcNAQkEMSIEIEgBjCiMhZLBevfHienSec11YNE+P7PSd4JD" +
	"wfCQCrwWMIGIBgkrBgEEAYI3EAQxezB5MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy" +
	"dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IFNIQTIg" +
	"QXNzdXJlZCBJRCBDQQIQBaTO8JYvDXElKlIYlJMocDCBigYLKoZIhvcNAQkQAgsxe6B5MGUxCzAJ" +
	"BgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j" +
	"b20xJDAiBgNVBAMTG0RpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDQQIQBaTO8JYvDXElKlIYlJMo" +
	"cDCBkwYJKoZIhvcNAQkPMYGFMIGCMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCgYIKoZIhvcN" +
	"AwcwCwYJYIZIAWUDBAECMA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDALBglghkgBZQME" +
	"AgEwCwYJYIZIAWUDBAIDMAsGCWCGSAFlAwQCAjAHBgUrDgMCGjANBgkqhkiG9w0BAQEFAASCAQBh" +
	"AjkUd98Si7LKxELWdwY8yrqrfK61JxVSxSY/BkF3xS/0QbQMU9Y+0V23nJX5ymamgCd9yNTdNapV" +
	"D4OzoVXfmTqd1/AD30M1a1CdBVoNGV8X4Uv8Z1fAl5MN+6Yt1CeIun39gvkutAgUmvCVrjFN+gD6" +
	"GH+VTQNGHr3wxdmtL9F8WeNECvpVgYEMqnYRrYHw4B6euJRsy4UnB4Sy/ogV1elkipxCbqRovPU1" +
	"pVeKhkfYuRlsLwbBwQPKvzcfUU3ZJua4I3AKKPxlqdY8uP72A5iObDTL8kHhSRMtVVHoruVzgJPZ" +
	"+9Mfsz41eM4pJSPDKZPYD9rH6cUKJI8xEnmCAAAAAAAA",
)

var fixtureMessageOutlookDetached = mustBase64Decode("" +
	"Q29udGVudC1UeXBlOiBtdWx0aXBhcnQvbWl4ZWQ7DQoJYm91bmRhcnk9Ii0t" +
	"LS09X05leHRQYXJ0XzAwMV8wMDFEXzAxRDM2OEY2LjdDRTk2MzcwIg0KDQoN" +
	"Ci0tLS0tLT1fTmV4dFBhcnRfMDAxXzAwMURfMDFEMzY4RjYuN0NFOTYzNzAN" +
	"CkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L2FsdGVybmF0aXZlOw0KCWJvdW5k" +
	"YXJ5PSItLS0tPV9OZXh0UGFydF8wMDJfMDAxRV8wMUQzNjhGNi43Q0U5NjM3" +
	"MCINCg0KDQotLS0tLS09X05leHRQYXJ0XzAwMl8wMDFFXzAxRDM2OEY2LjdD" +
	"RTk2MzcwDQpDb250ZW50LVR5cGU6IHRleHQvcGxhaW47DQoJY2hhcnNldD0i" +
	"dXMtYXNjaWkiDQpDb250ZW50LVRyYW5zZmVyLUVuY29kaW5nOiA3Yml0DQoN" +
	"CkhlcmUncyBhIG1lc3NhZ2Ugd2l0aCBhbiBTL01JTUUgc2lnbmF0dXJlIGFu" +
	"ZCBhbiBhdHRhY2htZW50Lg0KDQogDQoNCkp1c3QgY3VyaW91cyB3aGF0IHlv" +
	"dSdyZSBsb29raW5nIGF0IHNpZ25hdHVyZXMgZm9yPw0KDQogDQoNCkhvcGUg" +
	"dGhpcyBoZWxwcyENCg0KT3Jlbg0KDQoNCi0tLS0tLT1fTmV4dFBhcnRfMDAy" +
	"XzAwMUVfMDFEMzY4RjYuN0NFOTYzNzANCkNvbnRlbnQtVHlwZTogdGV4dC9o" +
	"dG1sOw0KCWNoYXJzZXQ9InVzLWFzY2lpIg0KQ29udGVudC1UcmFuc2Zlci1F" +
	"bmNvZGluZzogcXVvdGVkLXByaW50YWJsZQ0KDQo8aHRtbCB4bWxuczp2PTNE" +
	"InVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206dm1sIiA9DQp4bWxuczpvPTNE" +
	"InVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206b2ZmaWNlOm9mZmljZSIgPQ0K" +
	"eG1sbnM6dz0zRCJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOm9mZmljZTp3" +
	"b3JkIiA9DQp4bWxuczptPTNEImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5j" +
	"b20vb2ZmaWNlLzIwMDQvMTIvb21tbCIgPQ0KeG1sbnM9M0QiaHR0cDovL3d3" +
	"dy53My5vcmcvVFIvUkVDLWh0bWw0MCI+PGhlYWQ+PE1FVEEgPQ0KSFRUUC1F" +
	"UVVJVj0zRCJDb250ZW50LVR5cGUiIENPTlRFTlQ9M0QidGV4dC9odG1sOyA9" +
	"DQpjaGFyc2V0PTNEdXMtYXNjaWkiPjxtZXRhIG5hbWU9M0RHZW5lcmF0b3Ig" +
	"Y29udGVudD0zRCJNaWNyb3NvZnQgV29yZCAxNSA9DQooZmlsdGVyZWQgbWVk" +
	"aXVtKSI+PHN0eWxlPjwhLS0NCi8qIEZvbnQgRGVmaW5pdGlvbnMgKi8NCkBm" +
	"b250LWZhY2UNCgl7Zm9udC1mYW1pbHk6IkNhbWJyaWEgTWF0aCI7DQoJcGFu" +
	"b3NlLTE6MiA0IDUgMyA1IDQgNiAzIDIgNDt9DQpAZm9udC1mYWNlDQoJe2Zv" +
	"bnQtZmFtaWx5OkNhbGlicmk7DQoJcGFub3NlLTE6MiAxNSA1IDIgMiAyIDQg" +
	"MyAyIDQ7fQ0KLyogU3R5bGUgRGVmaW5pdGlvbnMgKi8NCnAuTXNvTm9ybWFs" +
	"LCBsaS5Nc29Ob3JtYWwsIGRpdi5Nc29Ob3JtYWwNCgl7bWFyZ2luOjBpbjsN" +
	"CgltYXJnaW4tYm90dG9tOi4wMDAxcHQ7DQoJZm9udC1zaXplOjExLjBwdDsN" +
	"Cglmb250LWZhbWlseToiQ2FsaWJyaSIsc2Fucy1zZXJpZjt9DQphOmxpbmss" +
	"IHNwYW4uTXNvSHlwZXJsaW5rDQoJe21zby1zdHlsZS1wcmlvcml0eTo5OTsN" +
	"Cgljb2xvcjojMDU2M0MxOw0KCXRleHQtZGVjb3JhdGlvbjp1bmRlcmxpbmU7" +
	"fQ0KYTp2aXNpdGVkLCBzcGFuLk1zb0h5cGVybGlua0ZvbGxvd2VkDQoJe21z" +
	"by1zdHlsZS1wcmlvcml0eTo5OTsNCgljb2xvcjojOTU0RjcyOw0KCXRleHQt" +
	"ZGVjb3JhdGlvbjp1bmRlcmxpbmU7fQ0Kc3Bhbi5FbWFpbFN0eWxlMTcNCgl7" +
	"bXNvLXN0eWxlLXR5cGU6cGVyc29uYWwtY29tcG9zZTsNCglmb250LWZhbWls" +
	"eToiQ2FsaWJyaSIsc2Fucy1zZXJpZjsNCgljb2xvcjp3aW5kb3d0ZXh0O30N" +
	"Ci5Nc29DaHBEZWZhdWx0DQoJe21zby1zdHlsZS10eXBlOmV4cG9ydC1vbmx5" +
	"Ow0KCWZvbnQtZmFtaWx5OiJDYWxpYnJpIixzYW5zLXNlcmlmO30NCkBwYWdl" +
	"IFdvcmRTZWN0aW9uMQ0KCXtzaXplOjguNWluIDExLjBpbjsNCgltYXJnaW46" +
	"MS4waW4gMS4waW4gMS4waW4gMS4waW47fQ0KZGl2LldvcmRTZWN0aW9uMQ0K" +
	"CXtwYWdlOldvcmRTZWN0aW9uMTt9DQotLT48L3N0eWxlPjwhLS1baWYgZ3Rl" +
	"IG1zbyA5XT48eG1sPg0KPG86c2hhcGVkZWZhdWx0cyB2OmV4dD0zRCJlZGl0" +
	"IiBzcGlkbWF4PTNEIjEwMjYiIC8+DQo8L3htbD48IVtlbmRpZl0tLT48IS0t" +
	"W2lmIGd0ZSBtc28gOV0+PHhtbD4NCjxvOnNoYXBlbGF5b3V0IHY6ZXh0PTNE" +
	"ImVkaXQiPg0KPG86aWRtYXAgdjpleHQ9M0QiZWRpdCIgZGF0YT0zRCIxIiAv" +
	"Pg0KPC9vOnNoYXBlbGF5b3V0PjwveG1sPjwhW2VuZGlmXS0tPjwvaGVhZD48" +
	"Ym9keSBsYW5nPTNERU4tVVMgPQ0KbGluaz0zRCIjMDU2M0MxIiB2bGluaz0z" +
	"RCIjOTU0RjcyIj48ZGl2IGNsYXNzPTNEV29yZFNlY3Rpb24xPjxwID0NCmNs" +
	"YXNzPTNETXNvTm9ybWFsPkhlcmUmIzgyMTc7cyBhIG1lc3NhZ2Ugd2l0aCBh" +
	"biBTL01JTUUgc2lnbmF0dXJlIGFuZCBhbiA9DQphdHRhY2htZW50LjxvOnA+" +
	"PC9vOnA+PC9wPjxwIGNsYXNzPTNETXNvTm9ybWFsPjxvOnA+Jm5ic3A7PC9v" +
	"OnA+PC9wPjxwID0NCmNsYXNzPTNETXNvTm9ybWFsPkp1c3QgY3VyaW91cyB3" +
	"aGF0IHlvdSYjODIxNztyZSBsb29raW5nIGF0IHNpZ25hdHVyZXMgPQ0KZm9y" +
	"PzxvOnA+PC9vOnA+PC9wPjxwIGNsYXNzPTNETXNvTm9ybWFsPjxvOnA+Jm5i" +
	"c3A7PC9vOnA+PC9wPjxwID0NCmNsYXNzPTNETXNvTm9ybWFsPkhvcGUgdGhp" +
	"cyBoZWxwcyE8bzpwPjwvbzpwPjwvcD48cCA9DQpjbGFzcz0zRE1zb05vcm1h" +
	"bD5PcmVuPG86cD48L286cD48L3A+PHAgY2xhc3M9M0RNc29Ob3JtYWw+ID0N" +
	"CjxvOnA+PC9vOnA+PC9wPjwvZGl2PjwvYm9keT48L2h0bWw+DQotLS0tLS09" +
	"X05leHRQYXJ0XzAwMl8wMDFFXzAxRDM2OEY2LjdDRTk2MzcwLS0NCg0KLS0t" +
	"LS0tPV9OZXh0UGFydF8wMDFfMDAxRF8wMUQzNjhGNi43Q0U5NjM3MA0KQ29u" +
	"dGVudC1UeXBlOiB0ZXh0L3BsYWluOw0KCW5hbWU9InRlc3QudHh0Ig0KQ29u" +
	"dGVudC1UcmFuc2Zlci1FbmNvZGluZzogN2JpdA0KQ29udGVudC1EaXNwb3Np" +
	"dGlvbjogYXR0YWNobWVudDsNCglmaWxlbmFtZT0idGVzdC50eHQiDQoNCnRl" +
	"c3QNCi0tLS0tLT1fTmV4dFBhcnRfMDAxXzAwMURfMDFEMzY4RjYuN0NFOTYz" +
	"NzAtLQ0K",
)

func mustBase64Decode(b64 string) []byte {
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(b64))
	buf := new(bytes.Buffer)

	if _, err := io.Copy(buf, decoder); err != nil {
		panic(err)
	}

	return buf.Bytes()
}
