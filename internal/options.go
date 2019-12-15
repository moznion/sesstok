package internal

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
)

// Options represents CLI options.
type Options struct {
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

// GetRCFileFullPath returns the full path for RC file according to the Options model.
func (o *Options) GetRCFileFullPath() (string, error) {
	configurationFilePath := o.RCFilePath
	if configurationFilePath != "" {
		return configurationFilePath, nil
	}

	homeDir, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".sesstok.rc"), nil
}

// GetCredentialsFileFullPath returns the full path for the AWS credentials file according to the Options model.
func (o *Options) GetCredentialsFileFullPath() (string, error) {
	credentialsFilePath := o.CredentialsFilePath
	if credentialsFilePath != "" {
		return credentialsFilePath, nil
	}

	homeDir, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".aws", "credentials"), nil
}

// OptionsParser represents a parser for CLI options.
type OptionsParser struct {
	opts   *Options
	parser *flags.Parser
}

// NewOptionsParser returns a new OptionsParser instance.
func NewOptionsParser() *OptionsParser {
	var opts Options
	return &OptionsParser{
		opts:   &opts,
		parser: flags.NewParser(&opts, flags.Default),
	}
}

// ParseArgs parses the CLI arguments and converts that to the Options.
func (p *OptionsParser) ParseArgs(args []string) (*Options, error) {
	args, err := p.parser.ParseArgs(args)
	if err != nil {
		return nil, err
	}
	return p.opts, nil
}

// Usage shows the usage of this application.
func (p *OptionsParser) Usage() {
	p.parser.WriteHelp(os.Stdout)
}
