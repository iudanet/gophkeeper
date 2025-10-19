package iocli

//go:generate moq -out io_mock.go . IO

// IO
type IO interface {
	Println(a ...any)
	Printf(format string, a ...any)
	ReadInput(prompt string) (string, error)
	ReadPassword(prompt string) (string, error)
	Write(p []byte) (n int, err error)
}
