package haystack

import "github.com/github/go/errors"

func ThisWillPanicDeep() {
	panic("this is a panic")
}

func ThisWillPanic() {
	// Go deeper
	ThisWillPanicDeep()
}

func PanicRecover(client *Reporter) {
	defer func() {
		if err := recover(); err != nil {
			wrap := errors.Panic(err)
			client.ReportBlocking(wrap, nil)
		}
	}()

	ThisWillPanic()
}

func GetAnError(n int) error {
	switch n {
	case 1:
		return errors.New("This is error 1")

	case 2:
		return errors.New("This is error 2")

	case 3:
		return errors.New("This is error 3")

	default:
		return nil
	}
}
