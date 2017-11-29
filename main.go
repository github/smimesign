package main

import (
	"fmt"
	"os"

	"github.com/mastahyeti/certstore"
	"github.com/pborman/getopt/v2"
	"github.com/pkg/errors"
)

var (
	// Action flags
	helpFlag     = getopt.BoolLong("help", 'h', "print this help message")
	signFlag     = getopt.BoolLong("sign", 's', "make a signature")
	verifyFlag   = getopt.BoolLong("verify", 0, "verify a signature")
	listKeysFlag = getopt.BoolLong("list-keys", 0, "show keys")

	// Option flags
	localUserOpt   = getopt.StringLong("local-user", 'u', "", "use USER-ID to sign", "USER-ID")
	detachSignFlag = getopt.BoolLong("detach-sign", 'b', "make a detached signature")
	armorFlag      = getopt.BoolLong("armor", 'a', "create ascii armored output")
	statusFdOpt    = getopt.IntLong("status-fd", 0, -1, "Write special status strings to the file descriptor n.", "n")
	keyFormatOpt   = getopt.EnumLong("keyid-format", 0, []string{"long"}, "long", "Select  how  to  display key IDs.", "{long}")
	fileArgs       []string

	idents []certstore.Identity
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

func faile(err error, message string) {
	fail(errors.Wrap(err, message))
}

func failef(err error, format string, a ...interface{}) {
	fail(errors.Wrapf(err, format, a...))
}

func fail(a ...interface{}) {
	fmt.Fprintln(os.Stderr, a...)
	panic(statusCode(1))
}

func failf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	panic(statusCode(1))
}
