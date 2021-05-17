package pinentry

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Pinentry gets the PIN from the user to access the smart card or hardware key
type Pinentry struct {
	path string
}

// NewPinentry initializes the pinentry program used to get the PIN
func NewPinentry() (*Pinentry, error) {
	fromEnv := os.Getenv("SMIMESIGM_PINENTRY")
	if len(fromEnv) > 0 {
		pinentryFromEnv, err := exec.LookPath(fromEnv)
		if err == nil && len(pinentryFromEnv) > 0 {
			return &Pinentry{path: pinentryFromEnv}, nil
		}
	}

	for _, programName := range paths {
		pinentry, err := exec.LookPath(programName)
		if err == nil && len(pinentry) > 0 {
			return &Pinentry{path: pinentry}, nil
		}
	}

	return nil, fmt.Errorf("failed to find suitable program to enter pin")
}

// Get executes the pinentry program and returns the PIN entered by the user
// see https://www.gnupg.org/documentation/manuals/assuan/Introduction.html for more details
func (pin *Pinentry) Get(prompt string) (string, error) {
	cmd := exec.Command(pin.path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	err = cmd.Start()
	if err != nil {
		return "", err
	}

	bufferReader := bufio.NewReader(stdout)
	lineBytes, _, err := bufferReader.ReadLine()
	if err != nil {
		return "", err
	}

	line := string(lineBytes)
	if !strings.HasPrefix(line, "OK") {
		return "", fmt.Errorf("failed to initialize pinentry, got response: %v", line)
	}

	terminal := os.Getenv("TERM")
	if len(terminal) > 0 {
		if ok := setOption(stdin, bufferReader, fmt.Sprintf("OPTION ttytype=%s\n", terminal)); !ok {
			return "", fmt.Errorf("failed to set ttytype")
		}
	}

	if ok := setOption(stdin, bufferReader, fmt.Sprintf("OPTION ttyname=%v\n", tty)); !ok {
		return "", fmt.Errorf("failed to set ttyname")
	}

	if ok := setOption(stdin, bufferReader, "SETPROMPT PIN:\n"); !ok {
		return "", fmt.Errorf("failed to set prompt")
	}
	if ok := setOption(stdin, bufferReader, "SETTITLE smimesign\n"); !ok {
		return "", fmt.Errorf("failed to set title")
	}
	if ok := setOption(stdin, bufferReader, fmt.Sprintf("SETDESC %s\n", prompt)); !ok {
		return "", fmt.Errorf("failed to set description")
	}

	_, err = fmt.Fprint(stdin, "GETPIN\n")
	if err != nil {
		return "", err
	}

	lineBytes, _, err = bufferReader.ReadLine()
	if err != nil {
		return "", err
	}

	line = string(lineBytes)

	_, err = fmt.Fprint(stdin, "BYE\n")
	if err != nil {
		return "", err
	}

	if err = cmd.Wait(); err != nil {
		return "", err
	}

	if !strings.HasPrefix(line, "D ") {
		return "", fmt.Errorf(line)
	}

	return strings.TrimPrefix(line, "D "), nil
}

func setOption(writer io.Writer, bufferedReader *bufio.Reader, option string) bool {
	_, err := fmt.Fprintf(writer, option)
	lineBytes, _, err := bufferedReader.ReadLine()
	if err != nil {
		return false
	}

	line := string(lineBytes)
	if !strings.HasPrefix(line, "OK") {
		return false
	}
	return true
}
