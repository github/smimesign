// +build !windows

package main
func parseRoots(roots *x509.CertPool ) error{
	roots, err := x509.SystemCertPool()
	if err != nil {
		return errors.Wrap(err, "Failed to parse root store")
	}

	for _, ident := range idents {
		if cert, err := ident.Certificate(); err == nil {
			roots.AddCert(cert)
		}
	}
	return nil
}
