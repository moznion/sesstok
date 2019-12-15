package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadMasterPassword_NoPassword(t *testing.T) {
	opt := &Options{
		PasswordRequired: false,
		Password:         "",
	}
	password, err := LoadMasterPassword(opt)
	assert.NoError(t, err)
	assert.EqualValues(t, make([]byte, 0), password)
}

func TestReadMasterPassword_WithPasswordViaCLI(t *testing.T) {
	{
		opt := &Options{
			PasswordRequired: true,
			Password:         "PSWD",
		}
		password, err := LoadMasterPassword(opt)
		assert.NoError(t, err)
		assert.EqualValues(t, []byte("PSWD"), password)
	}

	{
		opt := &Options{
			PasswordRequired: false,
			Password:         "PSWD",
		}
		password, err := LoadMasterPassword(opt)
		assert.NoError(t, err)
		assert.EqualValues(t, []byte("PSWD"), password)
	}
}

func TestReadMasterPassword_WithTerminalPassword(t *testing.T) {
	opt := &Options{
		PasswordRequired: true,
		Password:         "",
	}
	_, err := LoadMasterPassword(opt)

	// XXX check whether it goes terminal input mode
	assert.EqualError(t, err, "operation not supported by device")
}
