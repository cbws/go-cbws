package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gofrs/flock"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

// ErrNoToken is what a Store returns when it holds no token at all, as
// opposed to holding one that cannot be used. A caller that has other
// credentials to try should treat it as "look elsewhere" rather than as a
// failure.
var ErrNoToken = errors.New("no token stored")

// Store is where TokenSource reads and writes the OAuth token, and how it
// keeps processes from refreshing the same token at once.
//
// The Accounts service issues single-use rotating refresh tokens, so a
// refresh is a read-modify-write of shared state rather than a private
// operation: two processes that refresh the same stored token concurrently
// make one of them present an already-used token, which trips reuse
// detection and revokes the whole grant chain. Lock is what makes the
// sequence atomic across processes, and Load under that lock is what lets a
// process notice that someone else already rotated the token.
//
// The interface is exported so an application can keep ownership of its own
// configuration format. FileStore is the default for the CBWS CLI
// configuration file.
type Store interface {
	// Load returns the stored token, or ErrNoToken when none is stored.
	Load() (*oauth2.Token, error)

	// Save replaces the stored token. Everything else the underlying
	// storage holds must survive.
	Save(token *oauth2.Token) error

	// Lock takes an exclusive cross-process lock over the storage and
	// returns the function that releases it. Callers must not nest it.
	//
	// The lock is only worth as much as its adoption: every writer of the
	// credential has to take it, not only this package. An application
	// that logs in, logs out or replaces the token behind the same
	// storage must do so under this same lock, or a refresh can interleave
	// with it and write back a credential that a logout had removed.
	Lock() (unlock func(), err error)
}

// lockTimeout bounds how long acquiring the lock is worth waiting for. A
// process that dies holding the lock releases it when the kernel closes its
// descriptor, but a filesystem where locking does not work at all would
// otherwise hang every command forever.
//
// It is a variable so a test can reach the timeout without waiting it out.
var lockTimeout = 30 * time.Second

// lockRetryInterval is how often a waiting process retries the lock. It is
// short enough that the common case, a lock held for one token request,
// costs no perceptible delay.
const lockRetryInterval = 100 * time.Millisecond

// tokenKey is the configuration key the token lives under, and the shape
// every CBWS CLI version has written.
const tokenKey = "oauth_token"

// FileStore keeps the token in a YAML configuration file, the shape the
// CBWS CLI writes to ~/.cbws.yaml.
type FileStore struct {
	path string
}

// NewFileStore returns a Store over the YAML configuration file at path.
// The file does not have to exist yet.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// storedToken is the on-disk shape. The keys are lower-cased field names
// because that is what the CLI's YAML encoder produces for an oauth2.Token,
// and the two have to read each other's writes.
//
// Expiry is a string rather than a time.Time so that a value which is not a
// timestamp is a property of one field rather than a parse failure over the
// whole file.
type storedToken struct {
	AccessToken  string `yaml:"accesstoken"`
	TokenType    string `yaml:"tokentype"`
	RefreshToken string `yaml:"refreshtoken"`
	Expiry       string `yaml:"expiry"`
}

// Load implements Store.
func (s *FileStore) Load() (*oauth2.Token, error) {
	content, err := os.ReadFile(s.path)
	if err != nil {
		// A missing file is reported as it is, so a caller walking a list
		// of credential sources can tell "not configured" from "broken".
		return nil, err
	}

	var document struct {
		OAuthToken *storedToken `yaml:"oauth_token"`
	}
	if err := yaml.Unmarshal(content, &document); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", s.path, err)
	}

	if document.OAuthToken == nil {
		return nil, ErrNoToken
	}

	return document.OAuthToken.token(), nil
}

// token converts the stored shape into the oauth2 one.
//
// An expiry that does not parse takes the access token with it. A zero
// Expiry means "never expires" to oauth2.Token.Valid, so keeping the access
// token next to an unreadable expiry would hand out a bearer token of
// unknown age and never refresh it. Dropping it leaves an invalid token
// that still carries the refresh token, which is exactly the state a
// refresh starts from.
func (s *storedToken) token() *oauth2.Token {
	token := &oauth2.Token{
		TokenType:    s.TokenType,
		RefreshToken: s.RefreshToken,
	}

	expiry, err := time.Parse(time.RFC3339Nano, s.Expiry)
	if err != nil {
		return token
	}

	token.AccessToken = s.AccessToken
	token.Expiry = expiry

	return token
}

// Save implements Store. The file is rewritten with every other key left as
// it was, and replaced in one step so a concurrent reader sees either the
// whole old file or the whole new one.
func (s *FileStore) Save(token *oauth2.Token) error {
	path, err := s.resolvedPath()
	if err != nil {
		return err
	}

	content, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("could not read %s: %w", path, err)
	}

	var document yaml.MapSlice
	if err := yaml.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("could not parse %s: %w", path, err)
	}

	out, err := yaml.Marshal(setKey(document, tokenKey, stored(token)))
	if err != nil {
		return fmt.Errorf("could not encode %s: %w", path, err)
	}

	return replaceFile(path, out)
}

// resolvedPath follows a symlinked configuration file to its target, so the
// atomic replace below swaps the real file rather than the link. Dotfile
// managers commonly symlink the configuration into a checkout, and
// replacing the link would detach it from there silently.
//
// Resolution failing means one of two different things, and they cannot be
// treated alike. Nothing at the path at all is a configuration that has yet
// to be written, and the path is used as given. A symlink that does not
// resolve is a target that is missing or a loop, and falling back to the
// path there would replace the link itself, which is precisely the detaching
// this avoids.
func (s *FileStore) resolvedPath() (string, error) {
	resolved, err := filepath.EvalSymlinks(s.path)
	if err == nil {
		return resolved, nil
	}

	info, statErr := os.Lstat(s.path)
	if statErr != nil {
		return s.path, nil
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is a symlink that does not resolve: %w", s.path, err)
	}

	return s.path, nil
}

// stored converts a token into the on-disk shape.
//
// The expiry is always written as a timestamp, including the zero one. The
// field is read back with a timestamp parser, so leaving it empty for a
// token that carries no expiry would make the entry unreadable rather than
// make it say "no expiry".
func stored(token *oauth2.Token) storedToken {
	return storedToken{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry.Format(time.RFC3339Nano),
	}
}

// setKey replaces the value of key in document, appending it when the
// document does not have that key yet. Working on the parsed document
// rather than on a struct is what keeps configuration this package knows
// nothing about from being dropped on save.
func setKey(document yaml.MapSlice, key string, value any) yaml.MapSlice {
	for i, item := range document {
		if name, ok := item.Key.(string); ok && name == key {
			document[i].Value = value

			return document
		}
	}

	return append(document, yaml.MapItem{Key: key, Value: value})
}

// replaceFile writes content over path through a temporary file in the same
// directory, since a rename cannot cross a filesystem.
//
// An existing file keeps its permissions; a new one is owner-only, because
// what is being written is a credential.
func replaceFile(path string, content []byte) error {
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	dir := filepath.Dir(path)

	file, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("could not create a temporary file in %s: %w", dir, err)
	}
	defer os.Remove(file.Name())

	if err := writeAndClose(file, content, mode); err != nil {
		return err
	}

	if err := os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("could not replace %s: %w", path, err)
	}

	return syncDir(dir)
}

// syncDir flushes the directory entry the rename just changed. The file's
// own contents are already durable, but the rename that publishes them is a
// directory update, and a crash before that reaches the disk brings back the
// previous file, holding a refresh token that has since been spent.
//
// Only a platform saying it does not do this is ignored. A real I/O failure
// is reported, since a Save that cannot promise the rename survives a crash
// has not stored the token in the sense the caller needs.
func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("could not open %s to flush the replacement: %w", dir, err)
	}
	defer handle.Close()

	if err := handle.Sync(); err != nil && !syncUnsupported(err) {
		return fmt.Errorf("could not flush %s: %w", dir, err)
	}

	return nil
}

// syncUnsupported reports whether err means the platform does not sync
// directories at all, rather than that this sync failed. Windows refuses the
// operation on a directory handle outright, which is not a durability
// problem to report to a caller who cannot act on it.
func syncUnsupported(err error) bool {
	return errors.Is(err, errors.ErrUnsupported) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EACCES)
}

// writeAndClose fills the temporary file and closes it whatever goes wrong
// on the way, so a failed write never leaks the descriptor. It returns with
// the file closed, which is what lets the caller rename it.
func writeAndClose(file *os.File, content []byte, mode os.FileMode) error {
	// Close's own error is not reported: the data is durable once Sync has
	// returned, and every failure worth acting on has been raised by then.
	defer file.Close()

	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("could not set the mode of %s: %w", file.Name(), err)
	}

	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("could not write %s: %w", file.Name(), err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("could not flush %s: %w", file.Name(), err)
	}

	return nil
}

// Lock implements Store, with an advisory lock on a file next to the
// configuration. The lock is its own file rather than the configuration
// itself because Save replaces that file, which would leave each process
// holding a lock on a different inode.
func (s *FileStore) Lock() (func(), error) {
	path, err := s.resolvedPath()
	if err != nil {
		return nil, err
	}

	lock := flock.New(path + ".lock")

	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()

	locked, err := lock.TryLockContext(ctx, lockRetryInterval)
	switch {
	case locked:
		return func() { _ = lock.Unlock() }, nil

	// Running out of time is reported as the context's own error, which
	// says nothing about what was being waited for. Whoever sees this is
	// looking at a command that sat still for half a minute, so the message
	// has to name the file and point at the other process holding it.
	case ctx.Err() != nil:
		return nil, fmt.Errorf("timed out waiting %s for the lock on %s, another cbws process may be holding it", lockTimeout, lock.Path())

	case err != nil:
		return nil, fmt.Errorf("could not lock %s: %w", lock.Path(), err)

	default:
		return nil, fmt.Errorf("could not lock %s", lock.Path())
	}
}
