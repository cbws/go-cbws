package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

	projectName func(context.Context) (string, error)
}

// ProjectName reports the project the credentials belong to: the project
// named in a service account key, or the project of the machine whose
// metadata endpoint mints the tokens. Credentials that are not bound to a
// project, such as a user's CLI login, report an empty name and no error.
//
// It is a method rather than a field because the metadata endpoint has to be
// asked, and a caller that never wants the project should not pay for that.
func (c *Credentials) ProjectName(ctx context.Context) (string, error) {
	if c.projectName == nil {
		return "", nil
	}

	return c.projectName(ctx)
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
		projectName: func(context.Context) (string, error) {
			return credentials.ProjectName, nil
		},
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

	// First, try the environment variable.
	const envVar = "CBWS_CREDENTIALS"
	if filename := os.Getenv(envVar); filename != "" {
		creds, err := readCredentialsFile(ctx, filename, scopes, options)
		if err != nil {
			return nil, fmt.Errorf("cbws: error getting credentials using %v environment variable: %v", envVar, err)
		}
		return creds, nil
	}

	// Second, try the legacy spelling of the environment variable, which is
	// still read for setups that set only it.
	const legacyEnvVar = "CLOUDBEAR_CREDENTIALS"
	if filename := os.Getenv(legacyEnvVar); filename != "" {
		creds, err := readCredentialsFile(ctx, filename, scopes, options)
		if err != nil {
			return nil, fmt.Errorf("cbws: error getting credentials using %v environment variable: %v", legacyEnvVar, err)
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
	for _, filename := range cliConfigFiles() {
		credentials, err := resolved.cliCredentials(ctx, filename, scopes)
		if err != nil {
			return nil, err
		}
		if credentials != nil {
			return credentials, nil
		}
	}

	// Fifth, try the CBWS metadata token endpoint.
	//
	// Deliberately not cached. The endpoint is the same link-local address
	// on every machine and the service discloses no principal, so nothing
	// here distinguishes one machine's identity from another's; a cache
	// kept on shared storage would hand one machine's token to the next.
	// There is little to gain by taking that risk either: the source already
	// holds its token in memory for the token's lifetime, and a new process
	// is one link-local request away from one.
	if onCBWS() {
		return &Credentials{
			TokenSource: metadataTokenSource(ctx, scopes),
			projectName: metadataProjectName,
		}, nil
	}

	return nil, fmt.Errorf("no credentials found")
}

// onCBWS, metadataTokenSource and metadataProjectName are variables so tests
// can stand in for the link-local metadata server, which the metadata package
// probes once per process and addresses at a fixed endpoint.
var (
	onCBWS              = metadata.OnCBWS
	metadataTokenSource = func(ctx context.Context, scopes []string) oauth2.TokenSource {
		return metadata2.TokenSource(ctx, metadata2.WithScopes(scopes...))
	}
	metadataProjectName = metadata2.ProjectName
)

func wellKnownFile() string {
	return filepath.Join(guessUnixHomeDir(), ".config", "cbws", "credentials.json")
}

// cliConfigFiles is where the CBWS CLI keeps the credential this package
// reads when nothing else has supplied one, in the order they are tried.
//
// The CLI writes a dotfile, and has for as long as it has existed: its
// --config flag documents ~/.cbws.yaml, viper is pointed at it, and the
// file a refreshed token is persisted to is that one. The undotted name
// comes after it rather than instead of it, so a machine that somehow has
// one goes on working.
//
// A configuration named explicitly is the only one considered. Naming one
// and having another read instead would be answering a different question
// than the one asked.
func cliConfigFiles() []string {
	if path := os.Getenv("CBWS_CONFIG_FILE"); path != "" {
		return []string{path}
	}

	home := guessUnixHomeDir()

	return []string{
		filepath.Join(home, ".cbws.yaml"),
		filepath.Join(home, "cbws.yaml"),
	}
}

// cliCredentials reads the credential out of one CLI configuration.
//
// It returns nothing at all, and no error, for a configuration this lookup
// should step over: one that is not there, one that holds no credential,
// and one that is not a regular file. That last is why the check is made
// before the read rather than left to it. A directory would come back as
// an unreadable configuration rather than an absent one and fail the whole
// lookup, and a FIFO would not come back at all.
//
// A configuration that is there and cannot be read is still an error. The
// alternative is authenticating as somebody else because a file was
// malformed.
func (s *settings) cliCredentials(ctx context.Context, filename string, scopes []string) (*Credentials, error) {
	readable, err := isFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cbws: error reading CBWS CLI config file (%v): %v", filename, err)
	}
	if !readable {
		return nil, nil
	}

	// A path says where a credential is read from, not which login wrote
	// it, so this credential can only be cached once the application has
	// named the current one. Without that name a cache would go on serving
	// a token from before a logout, so there is no caching here and the
	// configuration goes on owning the access token, exactly as it does for
	// a caller with no cache at all.
	cacheable := s.cache != nil && s.generation != ""

	var storeOptions []cli.FileStoreOption
	if cacheable {
		storeOptions = append(storeOptions, cli.WithoutAccessToken())
	}

	tokenSource, err := cli.NewTokenSource(ctx, cli.NewFileStoreWithOptions(filename, storeOptions...), scopes)
	switch {
	case err == nil:

	case os.IsNotExist(err), errors.Is(err, cli.ErrNoToken):
		return nil, nil

	default:
		return nil, fmt.Errorf("cbws: error reading CBWS CLI config file (%v): %v", filename, err)
	}

	if !cacheable {
		return &Credentials{TokenSource: tokenSource}, nil
	}

	cached, err := s.cached(tokenSource, tokencache.Key{
		Issuer:     cli.Endpoint.TokenURL,
		Subject:    filename,
		Scopes:     scopes,
		Generation: s.generation,
	})
	if err != nil {
		return nil, err
	}

	return &Credentials{TokenSource: cached}, nil
}

// isFile reports whether path is something worth trying to read a
// credential out of, and separately whether the question could be answered
// at all.
//
// Not being there is an answer: there is no configuration, and the lookup
// moves on. So is being a directory or a pipe, which no configuration this
// package wrote ever is.
//
// Anything else is not an answer and must not be read as one. Something is
// at that path and this cannot tell what, so treating it as absent would
// step over a configuration that may hold a credential and carry on to
// authenticate as somebody else. A permission error and a symlink loop are
// that; so is a symlink whose target is missing, which has to be asked
// after twice, since a stat through a broken link reports the same absence
// as nothing being there at all.
func isFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		return info.Mode().IsRegular(), nil
	}

	if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}

	// Stat followed the link and found nothing. Lstat looks at the link
	// itself, which tells a credential location occupied by something
	// unresolvable from one that is genuinely empty.
	_, err = os.Lstat(path)
	switch {
	case err == nil:
		return false, fmt.Errorf("%s is a symlink that does not resolve", path)

	case errors.Is(err, fs.ErrNotExist):
		return false, nil

	default:
		return false, err
	}
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
