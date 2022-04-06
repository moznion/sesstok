package sesstok

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-ini/ini"
	"github.com/moznion/sesstok/internal"
	"golang.org/x/crypto/ssh/terminal"
)

const awsAccessKeyIDKey = "aws_access_key_id"
const awsSecretAccessKeyKey = "aws_secret_access_key"
const awsSessionTokenKey = "aws_session_token"

var (
	// ErrTokenCodeMissing is an error to indicate the mandatory argument `TokenCode` is missing.
	ErrTokenCodeMissing = errors.New("the required argument `TokenCode` was not provided")
)

// Run is the entry point of this application.
func Run(opts *internal.Options) error {
	if opts.Version {
		return internal.ShowVersion()
	}

	rcFilePath, err := opts.GetRCFileFullPath()
	if err != nil {
		return fmt.Errorf("failed to get rc file path: %w", err)
	}

	if _, err := os.Stat(rcFilePath); opts.Init || err != nil {
		fmt.Printf("rc file path: %s\n", rcFilePath)
		if err != nil {
			fmt.Printf("rc file doesn't exist\n")
		}
		err = initialize(rcFilePath)
		if err != nil {
			return fmt.Errorf("failed to initialize (rc file: %s): %w", rcFilePath, err)
		}
		fmt.Print("OK, please retry this command with token code :)\n")
		return nil
	}

	if opts.DumpRCFile {
		return dumpRCFile(opts, rcFilePath)
	}

	tokenCode := opts.Args.TokenCode
	if tokenCode == "" {
		return ErrTokenCodeMissing
	}

	pswd, err := internal.LoadMasterPassword(opts)
	if err != nil {
		return fmt.Errorf("failed to read master password: %w", err)
	}
	conf, err := internal.ReadRCFile(pswd, rcFilePath)
	if err != nil {
		return fmt.Errorf("failed to read rc file: %w", err)
	}

	sessToken, err := internal.RetrieveSessionToken(tokenCode, conf.AccessKeyID, conf.SecretAccessKey, opts.Duration, conf.MFASerial)
	if err != nil {
		return fmt.Errorf("failed to get STS session token: %w", err)
	}

	if !opts.Silent {
		fmt.Printf("%v\n", sessToken)
	}

	err = updateCredentials(opts, conf, sessToken)
	if err != nil {
		return fmt.Errorf("failed to update credentials file: %w", err)
	}

	return nil
}

func updateCredentials(opts *internal.Options, conf *internal.Config, sessToken *sts.GetSessionTokenOutput) error {
	if !opts.TokenOnly {
		credentialsFilePath, err := opts.GetCredentialsFileFullPath()
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

	conf := &internal.Config{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		MFASerial:       mfaSerial,
		ProfileName:     profileName,
	}

	err = conf.WriteRCFile(pswd, rcFilePath)
	if err != nil {
		return err
	}

	fmt.Printf("initialized (created rc file: %s)\n", rcFilePath)
	return nil
}

func dumpRCFile(opts *internal.Options, rcFilePath string) error {
	pswd, err := internal.LoadMasterPassword(opts)
	if err != nil {
		return fmt.Errorf("failed to read master password: %w", err)
	}
	conf, err := internal.ReadRCFile(pswd, rcFilePath)
	if err != nil {
		return fmt.Errorf("failed to read rc file: %w", err)
	}
	serializedConf, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("failed to serialize the contents of rc file: %w", err)
	}
	fmt.Printf("%s\n", serializedConf)
	return nil
}
