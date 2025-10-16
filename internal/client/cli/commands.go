package cli

import (
	"context"
	"fmt"
	"os"
)

func (c *Cli) Run(ctx context.Context, command string, args []string) {
	switch command {
	case "register":
		if err := RunRegister(ctx, c.apiClient, c.boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "login":
		if err := RunLogin(ctx, c.apiClient, c.boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "logout":
		if err := RunLogout(ctx, c.apiClient, c.boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := RunStatus(ctx, c.boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "add":
		if err := RunAdd(ctx, args[1:], c.boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		if err := RunList(ctx, args[1:], c.boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "get":
		if err := RunGet(ctx, args[1:], c.boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "delete":
		if err := RunDelete(ctx, args[1:], c.boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "sync":
		if err := RunSync(ctx, c.apiClient, c.boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		PrintUsage()
		os.Exit(1)
	}
}
