package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestFileStoreLoad(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    oauth2.Token
		wantErr error
	}{
		{
			name:    "a stored token",
			content: expiredConfig,
			want: oauth2.Token{
				AccessToken:  "at-stale",
				TokenType:    "bearer",
				RefreshToken: "rt-0",
				Expiry:       time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "the four-space indentation the CLI writes",
			content: "oauth_token:\n" +
				"    accesstoken: at-cli\n" +
				"    tokentype: bearer\n" +
				"    refreshtoken: rt-cli\n" +
				"    expiry: 2199-01-01T00:00:00.123456789Z\n",
			want: oauth2.Token{
				AccessToken:  "at-cli",
				TokenType:    "bearer",
				RefreshToken: "rt-cli",
				Expiry:       time.Date(2199, 1, 1, 0, 0, 0, 123456789, time.UTC),
			},
		},
		{
			// What the CLI writes with token caching turned off. The
			// refresh token still has to come back, or there is no way
			// to obtain a token at all.
			name: "a token stored without its access token",
			content: "oauth_token:\n" +
				"    accesstoken: \"\"\n" +
				"    tokentype: bearer\n" +
				"    refreshtoken: rt-only\n" +
				"    expiry: 0001-01-01T00:00:00Z\n",
			want: oauth2.Token{TokenType: "bearer", RefreshToken: "rt-only"},
		},
		{
			name:    "a configuration holding no token",
			content: "project_name: my-project\n",
			wantErr: ErrNoToken,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := NewFileStore(writeConfig(t, test.content)).Load()

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("error = %v, want %v", err, test.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("Load: %+v", err)
			}
			if *token != test.want {
				t.Errorf("token = %+v, want %+v", *token, test.want)
			}
		})
	}
}

// TestFileStoreLoadDropsAccessTokenWithUnreadableExpiry pins the one case
// where losing data is the safe answer. A zero Expiry means "never expires"
// to oauth2.Token.Valid, so an access token kept next to an expiry that does
// not parse would be handed out forever without ever being refreshed.
func TestFileStoreLoadDropsAccessTokenWithUnreadableExpiry(t *testing.T) {
	content := "oauth_token:\n" +
		"    accesstoken: at-undated\n" +
		"    tokentype: bearer\n" +
		"    refreshtoken: rt-0\n" +
		"    expiry: \"\"\n"

	token, err := NewFileStore(writeConfig(t, content)).Load()
	if err != nil {
		t.Fatalf("Load: %+v", err)
	}

	if token.AccessToken != "" {
		t.Errorf("access token = %q, want it dropped rather than treated as never expiring", token.AccessToken)
	}
	if token.Valid() {
		t.Error("token reports itself valid, want it refreshed instead")
	}
	if token.RefreshToken != "rt-0" {
		t.Errorf("refresh token = %q, want it kept so a refresh is still possible", token.RefreshToken)
	}
}

func TestFileStoreLoadMissingFile(t *testing.T) {
	_, err := NewFileStore(filepath.Join(t.TempDir(), "absent.yaml")).Load()

	if !os.IsNotExist(err) {
		t.Errorf("error = %v, want one satisfying os.IsNotExist", err)
	}
}

// TestFileStoreSaveKeepsEverythingElse: the configuration file is the
// user's, and holds settings this package knows nothing about.
func TestFileStoreSaveKeepsEverythingElse(t *testing.T) {
	content := `project_name: my-project
format: json
compute:
    zone: nl-ein-1
oauth_token:
    accesstoken: at-stale
    tokentype: bearer
    refreshtoken: rt-0
    expiry: 2020-01-01T00:00:00Z
oauth_scopes:
    - openid
    - offline
`
	path := writeConfig(t, content)

	expiry := time.Date(2199, 1, 1, 0, 0, 0, 0, time.UTC)
	err := NewFileStore(path).Save(&oauth2.Token{
		AccessToken:  "at-new",
		TokenType:    "bearer",
		RefreshToken: "rt-new",
		Expiry:       expiry,
	})
	if err != nil {
		t.Fatalf("Save: %+v", err)
	}

	for key, want := range map[string]string{
		"project_name": "my-project",
		"format":       "json",
		"zone":         "nl-ein-1",
		"refreshtoken": "rt-new",
		"accesstoken":  "at-new",
	} {
		if got := storedValue(t, path, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read back: %+v", err)
	}
	if !strings.Contains(string(raw), "- openid") {
		t.Errorf("configuration lost oauth_scopes:\n%s", raw)
	}

	// Read back through the store, which is the contract that matters: a
	// token written here has to be loadable by the next process.
	token, err := NewFileStore(path).Load()
	if err != nil {
		t.Fatalf("Load after Save: %+v", err)
	}
	if !token.Expiry.Equal(expiry) {
		t.Errorf("expiry round-tripped as %v, want %v", token.Expiry, expiry)
	}
}

// TestFileStoreSaveCreatesOwnerOnlyFile: the file holds a credential, so a
// configuration this package creates must not be readable by anyone else.
func TestFileStoreSaveCreatesOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".cbws.yaml")

	if err := NewFileStore(path).Save(&oauth2.Token{RefreshToken: "rt-0"}); err != nil {
		t.Fatalf("Save: %+v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %+v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
}

// TestFileStoreSaveKeepsExistingMode: a user who widened or narrowed the
// permissions of their own configuration keeps that choice.
func TestFileStoreSaveKeepsExistingMode(t *testing.T) {
	path := writeConfig(t, expiredConfig)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("Chmod: %+v", err)
	}

	if err := NewFileStore(path).Save(&oauth2.Token{RefreshToken: "rt-1"}); err != nil {
		t.Fatalf("Save: %+v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %+v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("mode = %o, want the 640 the file already had", got)
	}
}

// TestFileStoreSaveWritesThroughSymlink: dotfile managers symlink the
// configuration into a checkout, and replacing the link rather than its
// target would detach it silently.
func TestFileStoreSaveWritesThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "cbws.yaml")
	if err := os.WriteFile(target, []byte(expiredConfig), 0o600); err != nil {
		t.Fatalf("could not write the link target: %+v", err)
	}

	link := filepath.Join(dir, ".cbws.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("could not create the symlink: %+v", err)
	}

	if err := NewFileStore(link).Save(&oauth2.Token{RefreshToken: "rt-1"}); err != nil {
		t.Fatalf("Save: %+v", err)
	}

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("Lstat: %+v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a regular file")
	}
	if got := storedValue(t, target, "refreshtoken"); got != "rt-1" {
		t.Errorf("target refresh token = %q, want rt-1 written through the link", got)
	}
}

// TestFileStoreLockExcludes: the lock is what keeps two processes from
// spending the same single-use refresh token, so it has to actually
// exclude. Separate FileStore values stand in for separate processes, which
// on a flock implementation is the same thing: the lock belongs to the open
// file rather than to the process.
func TestFileStoreLockExcludes(t *testing.T) {
	path := writeConfig(t, expiredConfig)

	unlock, err := NewFileStore(path).Lock()
	if err != nil {
		t.Fatalf("Lock: %+v", err)
	}

	held := make(chan error, 1)
	go func() {
		second, err := NewFileStore(path).Lock()
		if err == nil {
			second()
		}
		held <- err
	}()

	select {
	case err := <-held:
		t.Fatalf("the second lock was granted while the first was held (err = %v)", err)
	case <-time.After(250 * time.Millisecond):
	}

	unlock()

	select {
	case err := <-held:
		if err != nil {
			t.Errorf("second Lock after release: %+v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the second lock was never granted after the first was released")
	}
}

// TestFileStoreLockSurvivesSave: Save replaces the configuration file, so
// locking the file itself would leave each process holding a lock on a
// different inode. The lock lives beside it for that reason.
func TestFileStoreLockSurvivesSave(t *testing.T) {
	path := writeConfig(t, expiredConfig)
	store := NewFileStore(path)

	unlock, err := store.Lock()
	if err != nil {
		t.Fatalf("Lock: %+v", err)
	}
	defer unlock()

	if err := store.Save(&oauth2.Token{RefreshToken: "rt-1"}); err != nil {
		t.Fatalf("Save: %+v", err)
	}

	granted := make(chan struct{})
	go func() {
		second, err := NewFileStore(path).Lock()
		if err == nil {
			second()
		}
		close(granted)
	}()

	select {
	case <-granted:
		t.Error("the lock stopped excluding once the configuration was replaced")
	case <-time.After(250 * time.Millisecond):
	}
}
