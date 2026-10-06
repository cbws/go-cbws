package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	metadata "go.cbws.cloud/sdk/cbws/metadata/v1alpha1"
	"go.cbws.cloud/sdk/oauth2/cli"
	metadata2 "go.cbws.cloud/sdk/oauth2/metadata"
	service_account "go.cbws.cloud/sdk/oauth2/service-account"
	"go.cbws.cloud/sdk/oauth2/tokencache"

	"golang.org/x/oauth2"
)

type Credentials struct {
	TokenSource oauth2.TokenSource
	JSON        []byte
}

func NewFromJSON(ctx context.Context, data []byte, scopes []string) (*Credentials, error) {
	return NewFromJSONWithOptions(ctx, data, scopes)
}

// NewFromJSONWithOptions is NewFromJSON with the options a caller may want
// applied to the resulting source, such as WithTokenCache.
func NewFromJSONWithOptions(ctx context.Context, data []byte, scopes []string, options ...Option) (*Credentials, error) {
	credentials := service_account.Credentials{}

	err := json.Unmarshal(data, &credentials)
	if err != nil {
		return nil, fmt.Errorf("could not parse credentials: %+v", err)
	}

	tokenSource, err := credentials.TokenSource(ctx, scopes)
	if err != nil {
		return nil, err
	}

	// The key names the account rather than anything in its key file: the
	// client id identifies the principal, and nothing derived from the
	// private key belongs in a cache identifier.
	tokenSource, err = newSettings(options).cached(tokenSource, tokencache.Key{
		Issuer:  service_account.TokenURL(),
		Subject: credentials.ClientID,
		Scopes:  scopes,
	})
	if err != nil {
		return nil, err
	}

	return &Credentials{
		TokenSource: tokenSource,
		JSON:        data,
	}, nil
}

func FindDefaultCredentials(ctx context.Context, scopes ...string) (*Credentials, error) {
	return FindDefaultCredentialsWithOptions(ctx, scopes)
}

// FindDefaultCredentialsWithOptions is FindDefaultCredentials with the
// options a caller may want applied to whichever credential is found, such
// as WithTokenCache.
//
// Every source that mints its tokens requests scopes for them: a service
// account key and the CBWS metadata endpoint. The CBWS CLI configuration
// cannot, because it holds a token whose scopes were fixed when the user
// logged in and a refresh cannot widen them; there scopes only separate
// cached tokens. Either way the authorization server decides what is
// granted, so a requested scope is not a guarantee that the token carries it.
func FindDefaultCredentialsWithOptions(ctx context.Context, scopes []string, options ...Option) (*Credentials, error) {
	resolved := newSettings(options)

	// First, try the legacy environment variable.
	const legacyEnvVar = "CLOUDBEAR_CREDENTIALS"
	if filename := os.Getenv(legacyEnvVar); filename != "" {
		creds, err := readCredentialsFile(ctx, filename, scopes, options)
		if err != nil {
			return nil, fmt.Errorf("cbws: error getting credentials using %v environment variable: %v", legacyEnvVar, err)
		}
		return creds, nil
	}

	// Second, try the environment variable.
	const envVar = "CBWS_CREDENTIALS"
	if filename := os.Getenv(envVar); filename != "" {
		creds, err := readCredentialsFile(ctx, filename, scopes, options)
		if err != nil {
			return nil, fmt.Errorf("cbws: error getting credentials using %v environment variable: %v", envVar, err)
		}
		return creds, nil
	}

	// Third, try a well-known file.
	filename := wellKnownFile()
	if creds, err := readCredentialsFile(ctx, filename, scopes, options); err == nil {
		return creds, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("cbws: error getting credentials using well-known file (%v): %v", filename, err)
	}

	// Fourth, try the CBWS CLI config. A file that is not there and a file
	// holding no token both mean the CLI is not logged in, which is a
	// reason to try the next source rather than to fail: a workload with a
	// metadata endpoint routinely has a configuration file for its project
	// name alone.
	filename = cliConfigFile()

	// A path says where a credential is read from, not which login wrote
	// it, so this credential can only be cached once the application has
	// named the current one. Without that name a cache would go on serving
	// a token from before a logout, so there is no caching here and the
	// configuration goes on owning the access token, exactly as it does for
	// a caller with no cache at all.
	cacheable := resolved.cache != nil && resolved.generation != ""

	var storeOptions []cli.FileStoreOption
	if cacheable {
		storeOptions = append(storeOptions, cli.WithoutAccessToken())
	}

	if tokenSource, err := cli.NewTokenSource(ctx, cli.NewFileStoreWithOptions(filename, storeOptions...), scopes); err == nil {
		if !cacheable {
			return &Credentials{TokenSource: tokenSource}, nil
		}

		cached, err := resolved.cached(tokenSource, tokencache.Key{
			Issuer:     cli.Endpoint.TokenURL,
			Subject:    filename,
			Scopes:     scopes,
			Generation: resolved.generation,
		})
		if err != nil {
			return nil, err
		}

		return &Credentials{TokenSource: cached}, nil
	} else if !os.IsNotExist(err) && !errors.Is(err, cli.ErrNoToken) {
		return nil, fmt.Errorf("cbws: error reading CBWS CLI config file (%v): %v", filename, err)
	}

	// Fifth, try the CBWS metadata token endpoint.
	//
	// Deliberately not cached. The endpoint is the same link-local address
	// on every machine and the service discloses no principal, so nothing
	// here distinguishes one machine's identity from another's; a cache
	// kept on shared storage would hand one machine's token to the next.
	// There is nothing to gain by taking that risk either, since these
	// tokens live a minute and the endpoint is a link-local request away.
	if onCBWS() {
		return &Credentials{TokenSource: metadataTokenSource(ctx, scopes)}, nil
	}

	return nil, fmt.Errorf("no credentials found")
}

// onCBWS and metadataTokenSource are variables so tests can stand in for the
// link-local metadata server, which the metadata package probes once per
// process and addresses at a fixed endpoint.
var (
	onCBWS              = metadata.OnCBWS
	metadataTokenSource = func(ctx context.Context, scopes []string) oauth2.TokenSource {
		return metadata2.TokenSource(ctx, metadata2.WithScopes(scopes...))
	}
)

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

func readCredentialsFile(ctx context.Context, filename string, scopes []string, options []Option) (*Credentials, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return NewFromJSONWithOptions(ctx, b, scopes, options...)
}
