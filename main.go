//go:generate goversioninfo -file-version=$GIT_VERSION -ver-major=$VERSION_MAJOR -ver-minor=$VERSION_MINOR -ver-patch=$VERSION_PATCH -platform-specific=true windows-installer/versioninfo.json

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/github/smimesign/certstore"
	"github.com/pborman/getopt/v2"
	"github.com/pkg/errors"
)

var (
	// This can be set at build time by running
	// go build -ldflags "-X main.versionString=$(git describe --tags)"
	versionString = "undefined"

	// default timestamp authority URL. This can be set at build time by running
	// go build -ldflags "-X main.defaultTSA=${https://whatever}"
	defaultTSA = ""

	// common usage error response if the user provides incompatible options
	usageError = errors.New("specify --help, --sign, --verify, or --list-keys")

	// Action flags
	helpFlag     = getopt.BoolLong("help", 'h', "print this help message")
	versionFlag  = getopt.BoolLong("version", 'v', "print the version number")
	signFlag     = getopt.BoolLong("sign", 's', "make a signature")
	jwtFlag      = getopt.BoolLong("jwt", 'j', "create and sign a JSON Web Token (JWT)")
	verifyFlag   = getopt.BoolLong("verify", 0, "verify a signature")
	listKeysFlag = getopt.BoolLong("list-keys", 0, "show keys")

	// Option flags
	localUserOpt    = getopt.StringLong("local-user", 'u', "", "use USER-ID to sign", "USER-ID")
	detachSignFlag  = getopt.BoolLong("detach-sign", 'b', "make a detached signature")
	armorFlag       = getopt.BoolLong("armor", 'a', "create ascii armored output")
	statusFdOpt     = getopt.IntLong("status-fd", 0, -1, "write special status strings to the file descriptor n.", "n")
	keyFormatOpt    = getopt.EnumLong("keyid-format", 0, []string{"long"}, "long", "select  how  to  display key IDs.", "{long}")
	tsaOpt          = getopt.StringLong("timestamp-authority", 't', defaultTSA, "URL of RFC3161 timestamp authority to use for timestamping", "url")
	includeCertsOpt = getopt.IntLong("include-certs", 0, -2, "-3 is the same as -2, but ommits issuer when cert has Authority Information Access extension. -2 includes all certs except root. -1 includes all certs. 0 includes no certs. 1 includes leaf cert. >1 includes n from the leaf. Default -2.", "n")

	// Remaining arguments
	fileArgs []string

	idents []certstore.Identity

	// these are changed in tests
	stdin  io.ReadCloser  = os.Stdin
	stdout io.WriteCloser = os.Stdout
	stderr io.WriteCloser = os.Stderr
)

func main() {
	if err := runCommand(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCommand() error {
	// Parse CLI args
	getopt.HelpColumn = 40
	getopt.SetParameters("[files]")
	getopt.Parse()
	fileArgs = getopt.Args()

	if *helpFlag {
		getopt.Usage()
		return nil
	}

	if *versionFlag {
		fmt.Println(versionString)
		return nil
	}

	// Open certificate store
	store, err := certstore.Open()
	if err != nil {
		return errors.Wrap(err, "failed to open certificate store")
	}
	defer store.Close()

	// Get list of identities
	idents, err = store.Identities()
	if err != nil {
		return errors.Wrap(err, "failed to get identities from certificate store")
	}
	for _, ident := range idents {
		defer ident.Close()
	}

	if *signFlag {
		if *verifyFlag || *listKeysFlag {
			return usageError
		} else if len(*localUserOpt) == 0 {
			return errors.New("specify a USER-ID to sign with")
		} else {
			return commandSign()
		}
	}

	if *jwtFlag {
		if *signFlag || *listKeysFlag {
			return usageError
		} else if len(*localUserOpt) == 0 {
			return errors.New("specify a USER-ID to sign with")
		} else {
			return commandJwt()
		}
	}

	if *verifyFlag {
		if *signFlag || *listKeysFlag {
			return usageError
		} else if len(*localUserOpt) > 0 {
			return errors.New("local-user cannot be specified for verification")
		} else if *detachSignFlag {
			return errors.New("detach-sign cannot be specified for verification")
		} else if *armorFlag {
			return errors.New("armor cannot be specified for verification")
		} else {
			return commandVerify()
		}
	}

	if *listKeysFlag {
		if *signFlag || *verifyFlag {
			return usageError
		} else if len(*localUserOpt) > 0 {
			return errors.New("local-user cannot be specified for list-keys")
		} else if *detachSignFlag {
			return errors.New("detach-sign cannot be specified for list-keys")
		} else if *armorFlag {
			return errors.New("armor cannot be specified for list-keys")
		} else {
			return commandListKeys()
		}
	}

	return usageError
}
