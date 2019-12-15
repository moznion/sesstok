package internal

import (
	"fmt"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// LoadMasterPassword loads the master password to encrypt/decrypt the RC file.
// This function has 3 patterns:
//   1. no password
//   2. password given through CLI option (`-P`)
//   3. password given through terminal (i.e. interactive mode)
func LoadMasterPassword(opts *Options) ([]byte, error) {
	pswdThroughCLI := opts.Password

	// when it doesn't have the `-p` option
	if !opts.PasswordRequired && pswdThroughCLI == "" {
		return make([]byte, 0), nil
	}

	// when it has the `-P` option
	if pswdThroughCLI != "" {
		return []byte(pswdThroughCLI), nil
	}

	fmt.Print("master password: ")
	pswd, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")
	return pswd, err
}
