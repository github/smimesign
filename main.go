package main

import (
	"fmt"
	"os"

	"github.com/pborman/getopt/v2"
)

var (
	// Action flags
	helpFlag   = getopt.BoolLong("help", 'h', "print this help message")
	signFlag   = getopt.BoolLong("sign", 's', "make a signature")
	verifyFlag = getopt.BoolLong("verify", 0, "verify a signature")

	// Option flags
	localUserOpt   = getopt.StringLong("local-user", 'u', "", "use USER-ID to sign", "USER-ID")
	detachSignFlag = getopt.BoolLong("detach-sign", 'b', "make a detached signature")
	armorFlag      = getopt.BoolLong("armor", 'a', "create ascii armored output")
	statusFdOpt    = getopt.IntLong("status-fd", 0, -1, "Write special status strings to the file descriptor n.", "n")
	keyFormatOpt   = getopt.EnumLong("keyid-format", 0, []string{"short", "0xshort", "long", "0xlong"}, "short", "Select  how  to  display key IDs.", "{short|0xshort|long|0xlong}")
)

func main() {
	getopt.HelpColumn = 30
	getopt.SetParameters("[files]")
	getopt.Parse()

	status := 1
	if *helpFlag {
		if *signFlag || *verifyFlag {
			fmt.Println("specify --help, --sign, or --verify")
		} else {
			getopt.Usage()
			status = 0
		}
	} else if *signFlag {
		if *helpFlag || *verifyFlag {
			fmt.Println("specify --help, --sign, or --verify")
		} else if len(*localUserOpt) == 0 {
			fmt.Println("specify a USER-ID to sign with")
		} else {
			status = commandSign()
		}
	} else if *verifyFlag {
		if *helpFlag || *signFlag {
			fmt.Println("specify --help, --sign, or --verify")
		} else if len(*localUserOpt) > 0 {
			fmt.Println("local-user cannot be specified for verification")
		} else if *detachSignFlag {
			fmt.Println("detach-sign cannot be specified for verification")
		} else if *armorFlag {
			fmt.Println("armor cannot be specified for verification")
		} else {
			status = commandVerify()
		}
	} else {
		fmt.Println("specify --help, --sign, or --verify")
	}

	os.Exit(status)
}
