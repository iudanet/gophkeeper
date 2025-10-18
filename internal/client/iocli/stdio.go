package iocli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

type Stdio struct{}

func NewStdio() IO {
	return &Stdio{}
}

func (s *Stdio) Println(a ...any) {
	fmt.Println(a...)
}

func (s *Stdio) Printf(format string, a ...any) {
	fmt.Printf(format, a...)
}

func (s *Stdio) ReadInput(prompt string) (string, error) {
	s.Printf("%s", prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

func (s *Stdio) ReadPassword(prompt string) (string, error) {
	s.Printf("%s", prompt)
	fd := int(os.Stdin.Fd())
	pwBytes, err := term.ReadPassword(fd)
	s.Println("")
	if err != nil {
		return "", err
	}
	return string(pwBytes), nil
}
