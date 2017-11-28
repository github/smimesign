package main

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/mastahyeti/cms"
)

func commandVerify() int {
	if len(fileArgs) < 2 {
		return verifyAttached()
	}

	return verifyDetached()
}

func verifyAttached() int {
	var (
		f   *os.File
		err error
	)

	// Read in signature
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			panic(err)
		}
		defer f.Close()
	} else {
		f = os.Stdin
	}

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		panic(err)
	}

	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		der = blk.Bytes
	} else {
		der = buf.Bytes()
	}

	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		panic(err)
	}

	// Verify signature
	if _, err = sd.Verify(cms.UnsafeNoVerify); err != nil {
		fmt.Printf("Sinature verification failed: %s\n", err.Error())
		return 1
	}

	fmt.Println("Signature verified")
	return 0
}

func verifyDetached() int {
	// Read in signature
	f, err := os.Open(fileArgs[0])
	if err != nil {
		panic(err)
	}
	defer f.Close()

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		panic(err)
	}

	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		der = blk.Bytes
	} else {
		der = buf.Bytes()
	}

	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		panic(err)
	}

	// Read in signed data
	if fileArgs[1] == "-" {
		f = os.Stdin
	} else {
		if f, err = os.Open(fileArgs[1]); err != nil {
			panic(err)
		}
		defer f.Close()
	}

	// Verify signature
	buf.Reset()
	if _, err = io.Copy(buf, f); err != nil {
		panic(err)
	}
	if _, err = sd.VerifyDetached(buf.Bytes(), cms.UnsafeNoVerify); err != nil {
		fmt.Printf("Sinature verification failed: %s\n", err.Error())
		return 1
	}

	fmt.Println("Signature verified")
	return 0
}
