package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/cbws/go-cbws/oauth2/cli"
	"github.com/cbws/go-cbws/oauth2/service-account"

	"golang.org/x/oauth2"
)

type Credentials struct {
	TokenSource oauth2.TokenSource
	JSON        []byte
}

func NewFromJSON(ctx context.Context, data []byte, scopes []string) (*Credentials, error) {
	credentials := service_account.Credentials{}

	err := json.Unmarshal(data, &credentials)
	if err != nil {
		return nil, fmt.Errorf("could not parse credentials: %+v", err)
	}

	tokenSource, err := credentials.TokenSource(ctx, scopes)
	if err != nil {
		return nil, err
	}
	return &Credentials{
		TokenSource: tokenSource,
		JSON:        data,
	}, err
}

func FindDefaultCredentials(ctx context.Context, scopes ...string) (*Credentials, error) {
	// First, try the environment variable.
	const envVar = "CLOUDBEAR_CREDENTIALS"
	if filename := os.Getenv(envVar); filename != "" {
		creds, err := readCredentialsFile(ctx, filename, scopes)
		if err != nil {
			return nil, fmt.Errorf("cloudbear: error getting credentials using %v environment variable: %v", envVar, err)
		}
		return creds, nil
	}

	// Second, try a well-known file.
	filename := wellKnownFile()
	if creds, err := readCredentialsFile(ctx, filename, scopes); err == nil {
		return creds, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("cloudbear: error getting credentials using well-known file (%v): %v", filename, err)
	}

	// Third, try the CBWS CLI config
	filename = cliConfigFile()
	if tokenSource, err := cli.NewTokenSourceFromConfig(ctx, filename, scopes); err == nil && tokenSource != nil {
		return &Credentials{TokenSource: tokenSource}, nil
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("cloudbear: error reading CBWS CLI config file (%v): %v", filename, err)
	}

	return nil, fmt.Errorf("no credentials found")
}

func wellKnownFile() string {
	return filepath.Join(guessUnixHomeDir(), ".config", "cbws", "credentials.json")
}

func cliConfigFile() string {
	if os.Getenv("CBWS_CONFIG_FILE") != "" {
		return os.Getenv("CBWS_CONFIG_FILE")
	}

	return filepath.Join(guessUnixHomeDir(), "cbws.yaml")
}

func guessUnixHomeDir() string {
	// Prefer $HOME over user.Current due to glibc bug: golang.org/issue/13470
	if v := os.Getenv("HOME"); v != "" {
		return v
	}
	// Else, fall back to user.Current:
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}

	return ""
}

func readCredentialsFile(ctx context.Context, filename string, scopes []string) (*Credentials, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return NewFromJSON(ctx, b, scopes)
}
