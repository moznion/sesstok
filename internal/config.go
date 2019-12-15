package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var encryptionConfiguration = &packet.Config{
	DefaultCipher: packet.CipherAES256,
}

// Config represents the AWS configuration for MFA.
type Config struct {
	AccessKeyID     string `json:"accessKeyID"`
	SecretAccessKey string `json:"secretAccessKey"`
	MFASerial       string `json:"mfaSerial"`
	ProfileName     string `json:"profileName"`
}

// ReadRCFile reads the contents of RC file and maps that to the config model.
func ReadRCFile(pswd []byte, rcFilePath string) (*Config, error) {
	file, _ := os.Open(rcFilePath)
	defer file.Close()

	prompt := func(passPhrase []byte) openpgp.PromptFunction {
		var called bool
		return func([]openpgp.Key, bool) ([]byte, error) {
			if called {
				return nil, errors.New("the passphrase is invalid; don't you forget to give `-p` option?")
			}
			called = true
			return passPhrase, nil
		}
	}
	md, err := openpgp.ReadMessage(file, nil, prompt(pswd), encryptionConfiguration)
	if err != nil {
		return nil, err
	}

	decrypted, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}

	var conf Config
	err = json.Unmarshal(decrypted, &conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

// WriteRCFile writes the config to a file.
func (c *Config) WriteRCFile(pswd []byte, rcFilePath string) error {
	serializedConf, err := json.Marshal(c)
	if err != nil {
		return err
	}

	buff := bytes.NewBuffer(nil)
	encrypt, err := openpgp.SymmetricallyEncrypt(buff, pswd, nil, encryptionConfiguration)
	if err != nil {
		return err
	}
	defer encrypt.Close()

	_, err = encrypt.Write(serializedConf)
	if err != nil {
		return err
	}

	_ = encrypt.Close() // flush

	err = ioutil.WriteFile(rcFilePath, buff.Bytes(), 0600)
	if err != nil {
		return err
	}

	return nil
}
