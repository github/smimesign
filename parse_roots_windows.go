// +build windows

package main

import (
	"crypto/x509"
	"github.com/certifi/gocertifi"
	"github.com/pkg/errors"
	"syscall"
	"unsafe"
)

const (
	CryptENotFound = 0x80092004
)

func parseRoots(roots *x509.CertPool) error{

	// The windows trust store is dynamically populated, to prevent issues with generally trusted
	// roots not being enumerated, use the mozilla trust store as a baseline
	roots, err := gocertifi.CACerts()
	if err != nil {
		roots = x509.NewCertPool()
	}

	// Enumerate the local machine trust store and add any missing certificates.
	storeName, err:= syscall.UTF16PtrFromString("Root")
	if err != nil {
		return errors.Wrap(err, "Failed to get root store name")
	}
	storeHandle, err := syscall.CertOpenSystemStore(0, storeName)
	if err != nil {
		return errors.New(syscall.GetLastError().Error())
	}
	defer syscall.CertCloseStore(storeHandle, 0)

	var cert *syscall.CertContext
	for {
		cert, err = syscall.CertEnumCertificatesInStore(storeHandle, cert)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == CryptENotFound {
					break
				}
			}
			return errors.New(syscall.GetLastError().Error())
		}
		if cert == nil {
			break
		}
		// Copy the buf, since ParseCertificate does not create its own copy.
		buf := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:]
		buf2 := make([]byte, cert.Length)
		copy(buf2, buf)
		if c, err := x509.ParseCertificate(buf2); err == nil {
			// AddCert contains logic to prevent adding a duplicate certificate to the pool
			roots.AddCert(c)
		}
	}




	return nil
}
