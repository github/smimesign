//go:generate goversioninfo -file-version=$GIT_VERSION -ver-major=$VERSION_MAJOR -ver-minor=$VERSION_MINOR -ver-patch=$VERSION_PATCH -platform-specific=true windows-installer/versioninfo.json

package main

import (
	"fmt"
	"io"
	"os"

	git "github.com/libgit2/git2go/v30"
	"github.com/github/certstore"
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

	// Action flags
	helpFlag     = getopt.BoolLong("help", 'h', "print this help message")
	versionFlag  = getopt.BoolLong("version", 'v', "print the version number")
	signFlag     = getopt.BoolLong("sign", 's', "make a signature")
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

	// read tsa and include-certs from gitconfig
	path, err := os.Getwd()
	if err == nil {
		repo, err := git.OpenRepository(path)
		if err == nil {
			config, err := repo.Config()

			tsa, err := config.LookupString("gpg.x509.smimesign.timestamp-authority")
			if err == nil {
				tsaOpt = &tsa
			}

			includeCerts32, err := config.LookupInt32("gpg.x509.smimesign.include-certs")
			if err == nil {
				var includeCerts int = int(includeCerts32)
				includeCertsOpt = &includeCerts
			}
		}
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
			return errors.New("specify --help, --sign, --verify, or --list-keys")
		} else if len(*localUserOpt) == 0 {
			return errors.New("specify a USER-ID to sign with")
		} else {
			return commandSign()
		}
	}

	if *verifyFlag {
		if *signFlag || *listKeysFlag {
			return errors.New("specify --help, --sign, --verify, or --list-keys")
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
			return errors.New("specify --help, --sign, --verify, or --list-keys")
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

	return errors.New("specify --help, --sign, --verify, or --list-keys")
}
