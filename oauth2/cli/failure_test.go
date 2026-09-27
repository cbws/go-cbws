package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// malformedConfig is YAML that no parser will accept, standing in for a
// configuration file an interrupted writer or a careless edit left behind.
const malformedConfig = "oauth_token: [unclosed\n"

func TestFileStoreLoadMalformedConfig(t *testing.T) {
	path := writeConfig(t, malformedConfig)

	_, err := NewFileStore(path).Load()
	if err == nil {
		t.Fatal("Load accepted malformed YAML")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %v, want it to name %s so the user can find the file", err, path)
	}
	if errors.Is(err, ErrNoToken) {
		t.Error("a malformed configuration reports ErrNoToken, which would make callers skip it silently")
	}
}

// TestFileStoreSaveRefusesMalformedConfig: rewriting a file that cannot be
// parsed would drop every setting in it, so the token is not worth the rest
// of the configuration.
func TestFileStoreSaveRefusesMalformedConfig(t *testing.T) {
	path := writeConfig(t, malformedConfig)

	if err := NewFileStore(path).Save(&oauth2.Token{RefreshToken: "rt-1"}); err == nil {
		t.Fatal("Save rewrote a configuration it could not parse")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read back: %+v", err)
	}
	if string(content) != malformedConfig {
		t.Errorf("the file was modified:\n%s", content)
	}
}

func TestFileStoreSaveIntoMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", ".cbws.yaml")

	if err := NewFileStore(path).Save(&oauth2.Token{RefreshToken: "rt-1"}); err == nil {
		t.Error("Save reported success for a path it cannot write")
	}
}

func TestFileStoreLockInMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", ".cbws.yaml")

	unlock, err := NewFileStore(path).Lock()
	if err == nil {
		unlock()
		t.Error("Lock reported success for a path it cannot create")
	}
}

// TestTokenDoesNotRefreshWhenTheStoreCannotBeReread: holding the lock but
// failing to re-read leaves the source unable to say whether its own copy
// has already been rotated by someone else. Refreshing on it anyway risks
// the replay, so the refresh is abandoned before the endpoint is contacted.
func TestTokenDoesNotRefreshWhenTheStoreCannotBeReread(t *testing.T) {
	endpoint := newFakeTokenEndpoint("rt-0")
	source, path := newTestSource(t, endpoint, expiredConfig)

	// Corrupted after the source loaded it, as a crashed writer would.
	if err := os.WriteFile(path, []byte(malformedConfig), 0o600); err != nil {
		t.Fatalf("could not corrupt the config: %+v", err)
	}

	_, err := source.Token()
	if err == nil {
		t.Fatal("Token refreshed against a store it could not re-read")
	}
	if !strings.Contains(err.Error(), "re-read") {
		t.Errorf("error = %v, want it to say the store could not be re-read", err)
	}
	if got := endpoint.calls(); got != 0 {
		t.Errorf("token endpoint received %d requests, want none", got)
	}
}

// TestTokenDoesNotUndoALogout: a token that disappears after we loaded it
// is what logging out looks like from here. Refreshing ours and saving the
// result would write the credential back and undo it.
func TestTokenDoesNotUndoALogout(t *testing.T) {
	endpoint := newFakeTokenEndpoint("rt-0")
	source, path := newTestSource(t, endpoint, expiredConfig)

	loggedOut := "project_name: my-project\n"
	if err := os.WriteFile(path, []byte(loggedOut), 0o600); err != nil {
		t.Fatalf("could not clear the stored token: %+v", err)
	}

	_, err := source.Token()
	if err == nil {
		t.Fatal("Token refreshed a credential that had been removed")
	}
	if !strings.Contains(err.Error(), "cbws init") {
		t.Errorf("error = %v, want it to say how to log back in", err)
	}
	if got := endpoint.calls(); got != 0 {
		t.Errorf("token endpoint received %d requests, want none", got)
	}

	content, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("could not read the config back: %+v", readErr)
	}
	if string(content) != loggedOut {
		t.Errorf("the logout was written back over:\n%s", content)
	}
}

// TestTokenAbortsOnAStoredEntryWithoutARefreshToken: an entry that carries
// no refresh token cannot say whether ours is still current, which is the
// one question the locked re-read exists to answer.
func TestTokenAbortsOnAStoredEntryWithoutARefreshToken(t *testing.T) {
	endpoint := newFakeTokenEndpoint("rt-0")
	source, path := newTestSource(t, endpoint, expiredConfig)

	orphaned := "oauth_token:\n" +
		"    accesstoken: at-orphan\n" +
		"    tokentype: bearer\n" +
		"    refreshtoken: \"\"\n" +
		"    expiry: 2020-01-01T00:00:00Z\n"
	if err := os.WriteFile(path, []byte(orphaned), 0o600); err != nil {
		t.Fatalf("could not write the orphaned token: %+v", err)
	}

	_, err := source.Token()
	if err == nil {
		t.Fatal("Token refreshed against an entry with no refresh token")
	}
	if got := endpoint.calls(); got != 0 {
		t.Errorf("token endpoint received %d requests, want none", got)
	}
}

// TestTokenKeepsOurTokenWhenStoredOneMatches: the same expired token on
// disk is not a rotation, and adopting it would be a no-op that costs a
// read. What matters is that it does not confuse the refresh.
func TestTokenKeepsOurTokenWhenStoredOneMatches(t *testing.T) {
	endpoint := newFakeTokenEndpoint("rt-0")
	source, _ := newTestSource(t, endpoint, expiredConfig)

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != "at-1" {
		t.Errorf("access token = %q, want the refreshed at-1", token.AccessToken)
	}
}

// TestValidTokenNeedsNoLock: the common case is a token that is still good,
// which must not take the cross-process lock at all. Taking it would make
// every command queue behind every other one.
func TestValidTokenNeedsNoLock(t *testing.T) {
	endpoint := newFakeTokenEndpoint()
	store := &countingStore{stubStore: stubStore{token: futureToken()}}

	source, err := NewTokenSource(context.Background(), store, nil, testEndpoint(t, endpoint), quietLogger())
	if err != nil {
		t.Fatalf("NewTokenSource: %+v", err)
	}

	for range 5 {
		if _, err := source.Token(); err != nil {
			t.Fatalf("Token: %+v", err)
		}
	}

	if got := store.locks(); got != 0 {
		t.Errorf("the store was locked %d times for a valid token, want none", got)
	}
	if got := endpoint.calls(); got != 0 {
		t.Errorf("token endpoint received %d requests, want none", got)
	}
}

// TestFailedRefreshIsRetried: a refresh that fails must not leave the
// source wedged. The next call has to try again, since the failure may have
// been the network rather than the token.
func TestFailedRefreshIsRetried(t *testing.T) {
	endpoint := newFakeTokenEndpoint() // accepts nothing, at first
	source, _ := newTestSource(t, endpoint, expiredConfig)

	if _, err := source.Token(); err == nil {
		t.Fatal("Token succeeded against an endpoint accepting nothing")
	}

	endpoint.mu.Lock()
	endpoint.accepted["rt-0"] = true
	endpoint.mu.Unlock()

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token after recovery: %+v", err)
	}
	if token.AccessToken != "at-1" {
		t.Errorf("access token = %q, want at-1", token.AccessToken)
	}
}

// TestLockIsReleasedAfterRefresh: the lock has to come back whether the
// refresh worked or not, or the next process waits out the whole timeout.
func TestLockIsReleasedAfterRefresh(t *testing.T) {
	for _, test := range []struct {
		name   string
		accept []string
	}{
		{name: "after a successful refresh", accept: []string{"rt-0"}},
		{name: "after a failed refresh"},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint := newFakeTokenEndpoint(test.accept...)
			path := writeConfig(t, expiredConfig)
			store := NewFileStore(path)

			source, err := NewTokenSource(context.Background(), store, nil, testEndpoint(t, endpoint), quietLogger())
			if err != nil {
				t.Fatalf("NewTokenSource: %+v", err)
			}

			_, _ = source.Token()

			unlock, err := NewFileStore(path).Lock()
			if err != nil {
				t.Fatalf("the lock was not released: %+v", err)
			}
			unlock()
		})
	}
}

func futureToken() *oauth2.Token {
	token := staleToken()
	token.AccessToken = "at-good"
	token.Expiry = token.Expiry.AddDate(500, 0, 0)

	return token
}

// countingStore records how often the source reaches for the lock.
type countingStore struct {
	stubStore

	mu     sync.Mutex
	locked int
}

func (s *countingStore) Lock() (func(), error) {
	s.mu.Lock()
	s.locked++
	s.mu.Unlock()

	return s.stubStore.Lock()
}

func (s *countingStore) locks() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.locked
}

// TestFileStoreLockTimesOut: a lock nobody releases must not hang the
// caller forever. The wait is bounded, and giving up is reported as an
// error the source then treats as "refresh without the lock".
func TestFileStoreLockTimesOut(t *testing.T) {
	path := writeConfig(t, expiredConfig)

	unlock, err := NewFileStore(path).Lock()
	if err != nil {
		t.Fatalf("Lock: %+v", err)
	}
	defer unlock()

	previous := lockTimeout
	lockTimeout = 200 * time.Millisecond
	defer func() { lockTimeout = previous }()

	start := time.Now()

	second, err := NewFileStore(path).Lock()
	if err == nil {
		second()
		t.Fatal("the second lock was granted while the first was held")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %v, want it to say the wait timed out", err)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Errorf("waited %v, want the wait bounded by the timeout", waited)
	}
}

// TestFileStoreSaveOverADirectory covers the read that opens Save: a path
// that is not a readable file is an error rather than an empty document,
// which would otherwise be rewritten as a configuration holding nothing but
// a token.
func TestFileStoreSaveOverADirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config-dir")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir: %+v", err)
	}

	if err := NewFileStore(path).Save(&oauth2.Token{RefreshToken: "rt-1"}); err == nil {
		t.Error("Save reported success over a directory")
	}
}

// TestReplaceFileReportsAFailedRename: the write can succeed and the swap
// still fail, and the caller has to hear about it rather than believe the
// token was stored.
func TestReplaceFileReportsAFailedRename(t *testing.T) {
	// A non-empty directory cannot be renamed over.
	path := filepath.Join(t.TempDir(), "occupied")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir: %+v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "child"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %+v", err)
	}

	err := replaceFile(path, []byte("oauth_token:\n"))
	if err == nil {
		t.Fatal("replaceFile reported success")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %v, want it to name %s", err, path)
	}

	leftover, readErr := os.ReadDir(filepath.Dir(path))
	if readErr != nil {
		t.Fatalf("ReadDir: %+v", readErr)
	}
	if len(leftover) != 1 {
		t.Errorf("the failed write left %d entries behind, want only the target", len(leftover))
	}
}

// TestWriteAndCloseReportsWhatFailed: the steps between creating the
// temporary file and renaming it can each fail, and every one of them has
// to be reported rather than leave a half-written file to be renamed over
// the configuration.
func TestWriteAndCloseReportsWhatFailed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %+v", err)
	}

	t.Run("a file that is already closed", func(t *testing.T) {
		file, err := os.OpenFile(path, os.O_RDWR, 0o600)
		if err != nil {
			t.Fatalf("OpenFile: %+v", err)
		}
		_ = file.Close()

		if err := writeAndClose(file, []byte("x"), 0o600); err == nil {
			t.Error("writeAndClose reported success on a closed file")
		}
	})

	t.Run("a file that cannot be written", func(t *testing.T) {
		file, err := os.Open(path)
		if err != nil {
			t.Fatalf("Open: %+v", err)
		}
		defer file.Close()

		err = writeAndClose(file, []byte("x"), 0o600)
		if err == nil {
			t.Fatal("writeAndClose reported success on a read-only descriptor")
		}
		if !strings.Contains(err.Error(), "could not write") {
			t.Errorf("error = %v, want it to say the write failed", err)
		}
	})
}

// TestFileStoreRejectsADanglingSymlink: a configuration symlinked to a
// target that is not there resolves to nothing. Falling back to the link
// path would replace the link with a regular file, detaching it from
// whatever manages it, which is the case following symlinks exists to
// avoid.
func TestFileStoreRejectsADanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, ".cbws.yaml")
	if err := os.Symlink(filepath.Join(dir, "gone.yaml"), link); err != nil {
		t.Fatalf("Symlink: %+v", err)
	}

	store := NewFileStore(link)

	t.Run("Save", func(t *testing.T) {
		err := store.Save(&oauth2.Token{RefreshToken: "rt-1"})
		if err == nil {
			t.Fatal("Save wrote through a symlink that does not resolve")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("error = %v, want it to say the symlink does not resolve", err)
		}

		info, statErr := os.Lstat(link)
		if statErr != nil {
			t.Fatalf("Lstat: %+v", statErr)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Error("the symlink was replaced by a regular file")
		}
	})

	t.Run("Lock", func(t *testing.T) {
		unlock, err := store.Lock()
		if err == nil {
			unlock()
			t.Error("Lock resolved a symlink that does not resolve")
		}
	})
}

// TestFileStoreSaveCreatesAConfigurationThatIsNotThere: resolution also
// fails when nothing exists at the path at all, and that case has to keep
// working. It is an ordinary first write, not a broken link.
func TestFileStoreSaveCreatesAConfigurationThatIsNotThere(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".cbws.yaml")

	if err := NewFileStore(path).Save(&oauth2.Token{RefreshToken: "rt-1"}); err != nil {
		t.Fatalf("Save: %+v", err)
	}

	if got := storedValue(t, path, "refreshtoken"); got != "rt-1" {
		t.Errorf("stored refresh token = %q, want rt-1", got)
	}
}

// TestSyncDirReportsARealFailure: a directory that cannot be opened is an
// I/O failure rather than a platform that does not sync directories, so it
// reaches the caller. A Save that cannot promise the rename survives a
// crash has not stored the token in the sense the caller needs.
func TestSyncDirReportsARealFailure(t *testing.T) {
	if err := syncDir(filepath.Join(t.TempDir(), "not-a-directory")); err == nil {
		t.Error("syncDir reported success for a directory that is not there")
	}
}

// TestSyncDirAcceptsAPlatformThatCannotSync: the errors a platform returns
// for refusing the operation outright are not durability failures to report
// to a caller who cannot act on them.
func TestSyncDirAcceptsAPlatformThatCannotSync(t *testing.T) {
	for _, err := range []error{errors.ErrUnsupported, syscall.EINVAL, syscall.EACCES} {
		if !syncUnsupported(err) {
			t.Errorf("syncUnsupported(%v) = false, want true", err)
		}
	}

	if syncUnsupported(syscall.EIO) {
		t.Error("syncUnsupported(EIO) = true, want a real I/O error reported")
	}
}

// TestSaveSyncsTheDirectory: the happy path has to actually reach syncDir,
// or the guarantee is only in the comment.
func TestSaveSyncsTheDirectory(t *testing.T) {
	path := writeConfig(t, expiredConfig)

	if err := NewFileStore(path).Save(&oauth2.Token{RefreshToken: "rt-1"}); err != nil {
		t.Fatalf("Save: %+v", err)
	}
	if got := storedValue(t, path, "refreshtoken"); got != "rt-1" {
		t.Errorf("stored refresh token = %q, want rt-1", got)
	}
}
