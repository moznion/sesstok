package sesstok

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-ini/ini"
	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh/terminal"
)

const awsAccessKeyIDKey = "aws_access_key_id"
const awsSecretAccessKeyKey = "aws_secret_access_key"
const awsSessionTokenKey = "aws_session_token"

var ver string
var rev string
var encryptionConfiguration = &packet.Config{
	DefaultCipher: packet.CipherAES256,
}

type options struct {
	RCFilePath          string                     `short:"r" long:"rc"                       description:"configuration file path of sesstok (default: $HOME/.sesstok.rc)"`
	CredentialsFilePath string                     `short:"c" long:"credentials"              description:"file path of AWS credentials (default: $HOME/.aws/credentials)"`
	PasswordRequired    bool                       `short:"p" long:"password"                 description:"use master password; if you've configured a master password, this option has to be specified'"`
	Password            string                     `short:"P"                                 description:"(NOT RECOMMENDED) pass the master password"`
	Duration            int64                      `short:"d" long:"duration" default:"86400" description:"duration of STS session token (unit: second)"`
	TokenOnly           bool                       `short:"t" long:"token-only"               description:"only retrieve STS session token (i.e. don't update credentials file)"`
	Silent              bool                       `short:"s" long:"silent"                   description:"silent mode"`
	Version             bool                       `short:"v" long:"version"                  description:"show the version"`
	DumpRCFile          bool                       `long:"dumprc"                             description:"dump rc file contents"`
	Init                bool                       `long:"init"                               description:"initialize a configuration (this option can be used with -r (--rc) options)"`
	Args                struct{ TokenCode string } `positional-args:"yes"`
}

type config struct {
	AccessKeyID     string `json:"accessKeyID"`
	SecretAccessKey string `json:"secretAccessKey"`
	MFASerial       string `json:"mfaSerial"`
	ProfileName     string `json:"profileName"`
}

// Run is the entrypoint of this application.
func Run(args []string) {
	var opts options
	args, err := flags.ParseArgs(&opts, args)
	if err != nil {
		// show help
		return
	}

	if opts.Version {
		fmt.Printf(`{"ver":"%s", "rev":"%s"}
`, ver, rev)
		return
	}

	rcFilePath, err := getRCFilePath(&opts)
	if err != nil {
		fmt.Printf("%s\n", errors.Wrap(err, "failed to get rc file path"))
		os.Exit(1)
	}

	if _, err := os.Stat(rcFilePath); opts.Init || err != nil {
		fmt.Printf("rc file path: %s\n", rcFilePath)
		if err != nil {
			fmt.Printf("rc file doesn't exist\n")
		}
		err = initialize(rcFilePath)
		if err != nil {
			fmt.Printf("%s\n", errors.Wrap(err, fmt.Sprintf("failed to initialize (rc file: %s)", rcFilePath)))
		}
		fmt.Print("OK, please retry this command with token code :)\n")
		return
	}

	if opts.DumpRCFile {
		pswd, err := readMasterPassword(&opts)
		if err != nil {
			fmt.Printf("%s\n", errors.Wrap(err, "failed to read master password"))
			os.Exit(1)
		}
		conf, err := readRCFile(rcFilePath, pswd)
		if err != nil {
			fmt.Printf("%s\n", errors.Wrap(err, "failed to read rc file"))
			os.Exit(1)
		}
		serializedConf, err := json.Marshal(conf)
		if err != nil {
			fmt.Printf("%s\n", errors.Wrap(err, "failed to serialize the contents of rc file"))
			os.Exit(1)
		}
		fmt.Printf("%s\n", serializedConf)
		return
	}

	tokenCode := opts.Args.TokenCode
	if tokenCode == "" {
		fmt.Print("the required argument `TokenCode` was not provided\n")
		os.Exit(1)
	}

	pswd, err := readMasterPassword(&opts)
	if err != nil {
		fmt.Printf("%s\n", errors.Wrap(err, "failed to read master password"))
		os.Exit(1)
	}
	conf, err := readRCFile(rcFilePath, pswd)
	if err != nil {
		fmt.Printf("%s\n", errors.Wrap(err, "failed to read rc file"))
		os.Exit(1)
	}

	sessToken, err := getSessionToken(tokenCode, &opts, conf)
	if err != nil {
		fmt.Printf("%s\n", errors.Wrap(err, "failed to get STS session token"))
		os.Exit(1)
	}

	if !opts.Silent {
		fmt.Printf("%v\n", sessToken)
	}

	err = updateCredentials(&opts, conf, sessToken)
	if err != nil {
		fmt.Printf("%s\n", errors.Wrap(err, "failed to update credentials file"))
		os.Exit(1)
	}
}

func writeRCFile(pswd []byte, rcFilePath string, conf *config) error {
	serializedConf, err := json.Marshal(conf)
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

func readRCFile(rcFilePath string, pswd []byte) (*config, error) {
	file, _ := os.Open(rcFilePath)
	defer file.Close()

	prompt := func(passPhrase []byte) openpgp.PromptFunction {
		var called bool
		return func([]openpgp.Key, bool) ([]byte, error) {
			if called {
				return nil, errors.New("the passphrase is invalid")
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

	var conf config
	err = json.Unmarshal(decrypted, &conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

func readMasterPassword(opts *options) ([]byte, error) {
	pswdThroughCLI := opts.Password
	if !opts.PasswordRequired && pswdThroughCLI == "" {
		return make([]byte, 0), nil
	}

	if pswdThroughCLI != "" {
		return []byte(pswdThroughCLI), nil
	}

	fmt.Print("master password: ")
	pswd, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")
	return pswd, err
}

func updateCredentials(opts *options, conf *config, sessToken *sts.GetSessionTokenOutput) error {
	if !opts.TokenOnly {
		credentialsFilePath, err := getCredentialsFilePath(opts)
		if err != nil {
			return err
		}
		allCreds, err := ini.Load(credentialsFilePath)
		if err != nil {
			return err
		}
		creds := allCreds.Section(conf.ProfileName)

		creds.Comment = fmt.Sprintf(`# {"sessionTokenExpiryDateTime":"%s"}`, sessToken.Credentials.Expiration.String())
		creds.Key(awsAccessKeyIDKey).SetValue(*sessToken.Credentials.AccessKeyId)
		creds.Key(awsSecretAccessKeyKey).SetValue(*sessToken.Credentials.SecretAccessKey)
		creds.Key(awsSessionTokenKey).SetValue(*sessToken.Credentials.SessionToken)

		err = allCreds.SaveTo(credentialsFilePath)
		if err != nil {
			return err
		}
	}

	return nil
}

func getSessionToken(totp string, opts *options, conf *config) (*sts.GetSessionTokenOutput, error) {
	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(conf.AccessKeyID, conf.SecretAccessKey, ""),
	})
	if err != nil {
		return nil, err
	}

	svc := sts.New(sess)
	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(opts.Duration),
		SerialNumber:    aws.String(conf.MFASerial),
		TokenCode:       aws.String(totp),
	}

	return svc.GetSessionToken(input)
}

func getCredentialsFilePath(opts *options) (string, error) {
	credentialsFilePath := opts.CredentialsFilePath
	if credentialsFilePath != "" {
		return credentialsFilePath, nil
	}

	homeDir, err := homedir.Dir()
	if err != nil {
		return "", errors.Wrap(err, "failed to get home directory")
	}
	return filepath.Join(homeDir, ".aws", "credentials"), nil
}

func getRCFilePath(opts *options) (string, error) {
	configurationFilePath := opts.RCFilePath
	if configurationFilePath != "" {
		return configurationFilePath, nil
	}

	homeDir, err := homedir.Dir()
	if err != nil {
		return "", errors.Wrap(err, "failed to get home directory")
	}
	return filepath.Join(homeDir, ".sesstok.rc"), nil
}

func initialize(rcFilePath string) error {
	fmt.Printf("would you like initialize? [N/y] ")
	var shouldInit string
	_, err := fmt.Scanf("%s", &shouldInit)
	if err != nil {
		return errors.New("abort")
	}
	shouldInit = strings.ToLower(shouldInit)
	if shouldInit != "y" && shouldInit != "yes" {
		return errors.New("abort")
	}

	fmt.Printf("would you like to set a master password? [N/y] ")
	var shouldSetMasterPswd string
	_, err = fmt.Scanf("%s", &shouldSetMasterPswd)
	if err != nil {
		return errors.New("abort")
	}
	shouldSetMasterPswd = strings.ToLower(shouldSetMasterPswd)

	pswd := make([]byte, 0)
	if shouldSetMasterPswd == "y" || shouldSetMasterPswd == "yes" {
		fmt.Print("master password: ")
		pswd, err = terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		fmt.Print("\nmaster password (confirm): ")
		confirmPswd, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
		if err != nil {
			return err
		}
		if string(pswd) != string(confirmPswd) {
			return errors.New("invalid password has come")
		}
		if string(pswd) == "" {
			return errors.New("empty password is not allowed")
		}
	}

	fmt.Print("access key ID for assume role: ")
	var accessKeyID string
	_, err = fmt.Scanf("%s", &accessKeyID)
	if err != nil {
		return err
	}

	fmt.Print("secret access key for assume role: ")
	var secretAccessKey string
	_, err = fmt.Scanf("%s", &secretAccessKey)
	if err != nil {
		return err
	}

	fmt.Print("MFA serial (ARN): ")
	var mfaSerial string
	_, err = fmt.Scanf("%s", &mfaSerial)
	if err != nil {
		return err
	}

	fmt.Print("profile name for assume role: ")
	var profileName string
	_, err = fmt.Scanf("%s", &profileName)
	if err != nil {
		return err
	}

	conf := &config{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		MFASerial:       mfaSerial,
		ProfileName:     profileName,
	}

	err = writeRCFile(pswd, rcFilePath, conf)
	if err != nil {
		return err
	}

	fmt.Printf("initialized (created rc file: %s)\n", rcFilePath)
	return nil
}
