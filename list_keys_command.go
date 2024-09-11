package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
)

func commandListKeys(showexp bool, onlydigisig bool) error {
	for _, ident := range idents {

		cert, err := ident.Certificate()
		if err != nil {
			fmt.Fprintln(os.Stderr, "WARNING:", errors.Wrap(err, "failed to get identity certificate"))
			continue
		}

		if !showexp {
			if cert.NotAfter.Before(time.Now()) {
				continue
			}
		}

		if onlydigisig {
			if (int(cert.KeyUsage) & int(x509.KeyUsageDigitalSignature)) == 0 {
				continue
			}
		}

		fmt.Println("       ID:", certHexFingerprint(cert))
		fmt.Println("      S/N:", cert.SerialNumber.Text(16))
		fmt.Println("Algorithm:", cert.SignatureAlgorithm.String())
		fmt.Println(" Validity:", cert.NotBefore.String(), "-", cert.NotAfter.String())
		fmt.Println("   Issuer:", cert.Issuer.ToRDNSequence().String())
		fmt.Println("  Subject:", cert.Subject.ToRDNSequence().String())
		fmt.Println("   Emails:", strings.Join(certEmails(cert), ", "))
		fmt.Println("Key Usage:", strings.Join(keyUsageToNames(cert.KeyUsage), ", "))
		fmt.Println("Ext.Usage:", strings.Join(certExtKeyUsages(cert), ", "))
		fmt.Print("\n")
	}

	return nil
}
