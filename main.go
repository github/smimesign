package main

import (
	"fmt"
	"os"

	"github.com/mastahyeti/certstore"
	"github.com/pborman/getopt/v2"
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

	store certstore.Store
)

func main() {
	// Open certificate store
	var err error
	if store, err = certstore.Open(); err != nil {
		panic(err)
	}
	defer store.Close()

	// Parse CLI args
	getopt.HelpColumn = 30
	getopt.SetParameters("[files]")
	getopt.Parse()
	fileArgs = getopt.Args()

	status := 1
	if *helpFlag {
		if *signFlag || *verifyFlag || *listKeysFlag {
			fmt.Println("specify --help, --sign, --verify, or --list-keys")
		} else {
			getopt.Usage()
			status = 0
		}
	} else if *signFlag {
		if *helpFlag || *verifyFlag || *listKeysFlag {
			fmt.Println("specify --help, --sign, --verify, or --list-keys")
		} else if len(*localUserOpt) == 0 {
			fmt.Println("specify a USER-ID to sign with")
		} else {
			status = commandSign()
		}
	} else if *verifyFlag {
		if *helpFlag || *signFlag || *listKeysFlag {
			fmt.Println("specify --help, --sign, --verify, or --list-keys")
		} else if len(*localUserOpt) > 0 {
			fmt.Println("local-user cannot be specified for verification")
		} else if *detachSignFlag {
			fmt.Println("detach-sign cannot be specified for verification")
		} else if *armorFlag {
			fmt.Println("armor cannot be specified for verification")
		} else {
			status = commandVerify()
		}
	} else if *listKeysFlag {
		if *helpFlag || *signFlag || *verifyFlag {
			fmt.Println("specify --help, --sign, --verify, or --list-keys")
		} else if len(*localUserOpt) > 0 {
			fmt.Println("local-user cannot be specified for list-keys")
		} else if *detachSignFlag {
			fmt.Println("detach-sign cannot be specified for list-keys")
		} else if *armorFlag {
			fmt.Println("armor cannot be specified for list-keys")
		} else {
			status = commandListKeys()
		}
	} else {
		fmt.Println("specify --help, --sign, --verify, or --list-keys")
	}

	os.Exit(status)
}
