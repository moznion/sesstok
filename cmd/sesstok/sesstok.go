package main

import (
	"os"

	"github.com/moznion/sesstok"
)

func main() {
	sesstok.Run(os.Args[1:])
}
