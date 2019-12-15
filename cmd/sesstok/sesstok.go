package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/moznion/sesstok"
	"github.com/moznion/sesstok/internal"
)

func main() {
	optsParser := internal.NewOptionsParser()
	args, err := optsParser.ParseArgs(os.Args[1:])
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			optsParser.Usage()
		}
		os.Exit(1)
	}

	err = sesstok.Run(args)
	if err != nil {
		fmt.Printf("[error] %s\n", err)
		if errors.Is(err, sesstok.ErrTokenCodeMissing) {
			optsParser.Usage()
		}
		os.Exit(1)
	}
}
