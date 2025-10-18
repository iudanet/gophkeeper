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

func (s *Stdio) Write(p []byte) (n int, err error) {
	// p содержит порцию байт, возможно без финального \n
	// Делаем безопасную преобразование и выводим через Println
	str := string(p)
	lines := strings.Split(str, "\n")
	for i, line := range lines {
		if i < len(lines)-1 {
			// Для всех строк кроме последней добавляем Println (с переводом строки)
			s.Println(line)
		} else {
			// Последняя может быть неполная, выводим Printf без новой строки
			if len(line) > 0 {
				s.Printf("%s", line)
			}
		}
	}

	return len(p), nil
}
