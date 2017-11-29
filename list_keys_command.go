package main

import (
	"fmt"
	"strings"
)

func commandListKeys() int {
	idents, err := store.Identities()
	if err != nil {
		panic(err)
	}
	for _, ident := range idents {
		defer ident.Close()
	}

	for j, ident := range idents {
		cert, err := ident.Certificate()
		if err != nil {
			panic(err)
		}

		if j > 0 {
			fmt.Println("————————————————————")
		}

		fmt.Println("       ID:", certHexFingerprint(cert))
		fmt.Println("      S/N:", cert.SerialNumber.Text(16))
		fmt.Println("Algorithm:", cert.SignatureAlgorithm.String())
		fmt.Println(" Validity:", cert.NotBefore.String(), "-", cert.NotAfter.String())
		fmt.Println("   Issuer:", rdnSequenceString(cert.Issuer.ToRDNSequence()))
		fmt.Println("  Subject:", rdnSequenceString(cert.Subject.ToRDNSequence()))
		fmt.Println("   Emails:", strings.Join(certEmails(cert), ", "))
	}

	return 0
}
