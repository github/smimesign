package main

import (
	"fmt"
	"strings"
)

func commandListKeys() {
	for j, ident := range idents {
		cert, err := ident.Certificate()
		if err != nil {
			faile(err, "failed to get identity certificate")
		}

		if j > 0 {
			fmt.Println("————————————————————")
		}

		fmt.Println("       ID:", certHexFingerprint(cert))
		fmt.Println("      S/N:", cert.SerialNumber.Text(16))
		fmt.Println("Algorithm:", cert.SignatureAlgorithm.String())
		fmt.Println(" Validity:", cert.NotBefore.String(), "-", cert.NotAfter.String())
		fmt.Println("   Issuer:", cert.Issuer.ToRDNSequence().String())
		fmt.Println("  Subject:", cert.Subject.ToRDNSequence().String())
		fmt.Println("   Emails:", strings.Join(certEmails(cert), ", "))
	}
}
