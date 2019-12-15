package internal

import (
	"encoding/json"
	"fmt"
)

// following arguments should be injected by `-ldflags` compiling option
var ver string
var rev string

type version struct {
	Ver      string `json:"version"`
	Revision string `json:"revision"`
}

// ShowVersion shows the version info.
func ShowVersion() error {
	vs, err := json.Marshal(&version{
		Ver:      ver,
		Revision: rev,
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", vs)
	return nil
}
