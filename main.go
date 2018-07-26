package main

import (
	"fmt"
	"io"
	"os"

	"github.com/mastahyeti/certstore"
	"github.com/pborman/getopt/v2"
	"github.com/pkg/errors"
)

var (
	// default timestamp authority URL. This can be set at build time by running
	// go build -ldflags "-X main.defaultTSA=${https://whatever}"
	defaultTSA = ""

	// Action flags
	helpFlag     = getopt.BoolLong("help", 'h', "print this help message")
	signFlag     = getopt.BoolLong("sign", 's', "make a signature")
	verifyFlag   = getopt.BoolLong("verify", 0, "verify a signature")
	listKeysFlag = getopt.BoolLong("list-keys", 0, "show keys")

	// Option flags
	localUserOpt    = getopt.StringLong("local-user", 'u', "", "use USER-ID to sign", "USER-ID")
	detachSignFlag  = getopt.BoolLong("detach-sign", 'b', "make a detached signature")
	armorFlag       = getopt.BoolLong("armor", 'a', "create ascii armored output")
	statusFdOpt     = getopt.IntLong("status-fd", 0, -1, "write special status strings to the file descriptor n.", "n")
	keyFormatOpt    = getopt.EnumLong("keyid-format", 0, []string{"long"}, "long", "select  how  to  display key IDs.", "{long}")
	tsaOpt          = getopt.StringLong("timestamp-authority", 't', defaultTSA, "URL of RFC3161 timestamp authority to use for timestamping")
	includeCertsOpt = getopt.IntLong("include-certs", 0, -3, "-3 is the same as -2, but ommits issuer when cert has Authority Information Access extension. -2 includes all certs except root. -1 includes all certs. 0 includes no certs. 1 includes leaf cert. >1 includes n from the leaf. Default -3.")

	// Remaining arguments
	fileArgs []string

	idents []certstore.Identity

	// these are changed in tests
	stdin  io.ReadCloser  = os.Stdin
	stdout io.WriteCloser = os.Stdout
	stderr io.WriteCloser = os.Stderr
)

func main() {
	defer handleExit()

	// Parse CLI args
	getopt.HelpColumn = 30
	getopt.SetParameters("[files]")
	getopt.Parse()
	fileArgs = getopt.Args()

	if *helpFlag {
		if *signFlag || *verifyFlag || *listKeysFlag {
			fail("specify --help, --sign, --verify, or --list-keys")
		} else {
			getopt.Usage()
			return
		}
	}

	// Open certificate store
	store, err := certstore.Open()
	if err != nil {
		faile(err, "failed to open certificate store")
	}
	defer store.Close()

	// Get list of identities
	idents, err = store.Identities()
	if err != nil {
		faile(err, "failed to get identities from certificate store")
	}
	for _, ident := range idents {
		defer ident.Close()
	}

	if *signFlag {
		if *helpFlag || *verifyFlag || *listKeysFlag {
			fail("specify --help, --sign, --verify, or --list-keys")
		} else if len(*localUserOpt) == 0 {
			fail("specify a USER-ID to sign with")
		} else {
			commandSign()
			return
		}
	}

	if *verifyFlag {
		if *helpFlag || *signFlag || *listKeysFlag {
			fail("specify --help, --sign, --verify, or --list-keys")
		} else if len(*localUserOpt) > 0 {
			fail("local-user cannot be specified for verification")
		} else if *detachSignFlag {
			fail("detach-sign cannot be specified for verification")
		} else if *armorFlag {
			fail("armor cannot be specified for verification")
		} else {
			commandVerify()
			return
		}
	}

	if *listKeysFlag {
		if *helpFlag || *signFlag || *verifyFlag {
			fail("specify --help, --sign, --verify, or --list-keys")
		} else if len(*localUserOpt) > 0 {
			fail("local-user cannot be specified for list-keys")
		} else if *detachSignFlag {
			fail("detach-sign cannot be specified for list-keys")
		} else if *armorFlag {
			fail("armor cannot be specified for list-keys")
		} else {
			commandListKeys()
			return
		}
	}

	fail("specify --help, --sign, --verify, or --list-keys")
}

type statusCode int

func handleExit() {
	if e := recover(); e != nil {
		if sc, isStatusCode := e.(statusCode); isStatusCode {
			os.Exit(int(sc))
		}

		panic(e)
	}
}

// actual fail implementation. overridden in tests.
func doFail(a ...interface{}) {
	fmt.Fprintln(stderr, a...)
	panic(statusCode(1))
}

type failerFunc func(...interface{})

var failer failerFunc = doFail

func fail(a ...interface{}) {
	failer(a...)
}

func faile(err error, message string) {
	fail(errors.Wrap(err, message))
}

func failef(err error, format string, a ...interface{}) {
	fail(errors.Wrapf(err, format, a...))
}
