package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

// This file implements gnupg's "status protocol". When the --status-fd argument
// is passed, gpg will output machine-readable status updates to that fd.
// Details on the "protocol" can be found at https://git.io/vFFKC

type status string

const (

	// SIG_CREATED <type> <pk_algo> <hash_algo> <class> <timestamp> <keyfpr>
	//   A signature has been created using these parameters.
	//   Values for type <type> are:
	//     - D :: detached
	//     - C :: cleartext
	//     - S :: standard
	//   (only the first character should be checked)
	//
	//   <class> are 2 hex digits with the OpenPGP signature class.
	//
	//   Note, that TIMESTAMP may either be a number of seconds since Epoch
	//   or an ISO 8601 string which can be detected by the presence of the
	//   letter 'T'.
	sSigCreated status = "SIG_CREATED"

	// NEWSIG [<signers_uid>]
	//   Is issued right before a signature verification starts.  This is
	//   useful to define a context for parsing ERROR status messages.
	//   arguments are currently defined.  If SIGNERS_UID is given and is
	//   not "-" this is the percent escape value of the OpenPGP Signer's
	//   User ID signature sub-packet.
	sNewSig status = "NEWSIG"

	// GOODSIG  <long_keyid_or_fpr>  <username>
	//   The signature with the keyid is good.  For each signature only one
	//   of the codes GOODSIG, BADSIG, EXPSIG, EXPKEYSIG, REVKEYSIG or
	//   ERRSIG will be emitted.  In the past they were used as a marker
	//   for a new signature; new code should use the NEWSIG status
	//   instead.  The username is the primary one encoded in UTF-8 and %XX
	//   escaped. The fingerprint may be used instead of the long keyid if
	//   it is available.  This is the case with CMS and might eventually
	//   also be available for OpenPGP.
	sGoodSig status = "GOODSIG"

	// VALIDSIG <args>
	//
	//     The args are:
	//
	//     - <fingerprint_in_hex>
	//     - <sig_creation_date>
	//     - <sig-timestamp>
	//     - <expire-timestamp>
	//     - <sig-version>
	//     - <reserved>
	//     - <pubkey-algo>
	//     - <hash-algo>
	//     - <sig-class>
	//     - [ <primary-key-fpr> ]
	//
	//     This status indicates that the signature is cryptographically
	//     valid. This is similar to GOODSIG, EXPSIG, EXPKEYSIG, or REVKEYSIG
	//     (depending on the date and the state of the signature and signing
	//     key) but has the fingerprint as the argument. Multiple status
	//     lines (VALIDSIG and the other appropriate *SIG status) are emitted
	//     for a valid signature.  All arguments here are on one long line.
	//     sig-timestamp is the signature creation time in seconds after the
	//     epoch. expire-timestamp is the signature expiration time in
	//     seconds after the epoch (zero means "does not
	//     expire"). sig-version, pubkey-algo, hash-algo, and sig-class (a
	//     2-byte hex value) are all straight from the signature packet.
	//     PRIMARY-KEY-FPR is the fingerprint of the primary key or identical
	//     to the first argument.  This is useful to get back to the primary
	//     key without running gpg again for this purpose.
	//
	//     The primary-key-fpr parameter is used for OpenPGP and not
	//     available for CMS signatures.  The sig-version as well as the sig
	//     class is not defined for CMS and currently set to 0 and 00.
	//
	//     Note, that *-TIMESTAMP may either be a number of seconds since
	//     Epoch or an ISO 8601 string which can be detected by the presence
	//     of the letter 'T'.
	sValidSig status = "VALIDSIG"

	// TRUST_
	//   These are several similar status codes:
	//
	//   - TRUST_UNDEFINED <error_token>
	//   - TRUST_NEVER     <error_token>
	//   - TRUST_MARGINAL  [0  [<validation_model>]]
	//   - TRUST_FULLY     [0  [<validation_model>]]
	//   - TRUST_ULTIMATE  [0  [<validation_model>]]
	//
	//   For good signatures one of these status lines are emitted to
	//   indicate the validity of the key used to create the signature.
	//   The error token values are currently only emitted by gpgsm.
	//
	//   VALIDATION_MODEL describes the algorithm used to check the
	//   validity of the key.  The defaults are the standard Web of Trust
	//   model for gpg and the standard X.509 model for gpgsm.  The
	//   defined values are
	//
	//      - pgp   :: The standard PGP WoT.
	//      - shell :: The standard X.509 model.
	//      - chain :: The chain model.
	//      - steed :: The STEED model.
	//      - tofu  :: The TOFU model
	//
	//   Note that the term =TRUST_= in the status names is used for
	//   historic reasons; we now speak of validity.
	sTrustUndefined status = "TRUST_UNDEFINED"
	sTrustNever     status = "TRUST_NEVER"
	sTrustMarginal  status = "TRUST_MARGINAL"
	sTrustFully     status = "TRUST_FULLY"
	sTrustUltimate  status = "TRUST_ULTIMATE"

	// VERIFICATION_COMPLIANCE_MODE <flags>
	//     Indicates that the current signature verification operation is in
	//     compliance with the given set of modes.  "flags" is a space
	//     separated list of numerical flags, see "Field 18 - Compliance
	//     flags" above.
	sVerificationComplianceMode = "VERIFICATION_COMPLIANCE_MODE"
)

var (
	setupStatus sync.Once
	statusFile  *os.File
)

func (s status) emit(format string, args ...interface{}) {
	setupStatus.Do(func() {
		if *statusFdOpt > 0 {
			// TODO: debugging output if this fails
			statusFile = os.NewFile(uintptr(*statusFdOpt), "status")
		}
	})

	if statusFile == nil {
		return
	}

	const prefix = "[GNUPG:] "
	statusFile.WriteString(prefix)
	statusFile.WriteString(string(s))
	fmt.Fprintf(statusFile, " "+format+"\n", args...)
}

func emitSigCreated(cert *x509.Certificate, isDetached bool) {
	// SIG_CREATED arguments
	var (
		sigType                    string
		pkAlgo, hashAlgo, sigClass byte
		now                        int64
		fpr                        string
	)

	if isDetached {
		sigType = "D"
	} else {
		sigType = "S"
	}

	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		pkAlgo = byte(packet.PubKeyAlgoRSA)
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		pkAlgo = byte(packet.PubKeyAlgoECDSA)
	}

	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		hashAlgo, _ = s2k.HashToHashId(crypto.SHA1)
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		hashAlgo, _ = s2k.HashToHashId(crypto.SHA256)
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		hashAlgo, _ = s2k.HashToHashId(crypto.SHA384)
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		hashAlgo, _ = s2k.HashToHashId(crypto.SHA512)
	}

	// gpgsm seems to always use 0x00
	sigClass = 0
	now = time.Now().Unix()
	fpr = certHexFingerprint(cert)

	sSigCreated.emit("%s %d %d %02x %d %s", sigType, pkAlgo, hashAlgo, sigClass, now, fpr)
}
