package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// tokenConfig is a CBWS CLI configuration of a logged-in user.
const tokenConfig = `project_name: my-project
oauth_token:
    accesstoken: at-stale
    tokentype: bearer
    refreshtoken: rt-0
    expiry: 2020-01-01T00:00:00Z
`

// isolate points every credential source this package consults at a scratch
// directory, so a test never picks up the credentials of whoever is running
// it and never writes to their configuration.
func isolate(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLOUDBEAR_CREDENTIALS", "")
	t.Setenv("CBWS_CREDENTIALS", "")
	t.Setenv("CBWS_CONFIG_FILE", filepath.Join(home, ".cbws.yaml"))

	return home
}

// TestFindDefaultCredentialsUsesCLIConfig covers the path a developer's own
// machine takes: no service account key anywhere, but the CLI is logged in.
func TestFindDefaultCredentialsUsesCLIConfig(t *testing.T) {
	home := isolate(t)

	if err := os.WriteFile(filepath.Join(home, ".cbws.yaml"), []byte(tokenConfig), 0o600); err != nil {
		t.Fatalf("could not write the config: %+v", err)
	}

	credentials, err := FindDefaultCredentials(context.Background())
	if err != nil {
		t.Fatalf("FindDefaultCredentials: %+v", err)
	}
	if credentials.TokenSource == nil {
		t.Error("credentials carry no token source")
	}

	// The configuration's project_name is where the CLI is switched to, not
	// a property of the login, so it is not the credential's project.
	name, err := credentials.ProjectName(context.Background())
	if err != nil || name != "" {
		t.Errorf("ProjectName() = %q, %v, want no project for a login", name, err)
	}
}

// TestFindDefaultCredentialsSkipsTokenlessConfig is the regression test for
// a configuration file that exists but holds no token, which every workload
// that sets a project name has. It used to fail the whole lookup, so a
// machine with a metadata endpoint could not authenticate at all once it had
// a configuration file.
func TestFindDefaultCredentialsSkipsTokenlessConfig(t *testing.T) {
	home := isolate(t)

	if err := os.WriteFile(filepath.Join(home, ".cbws.yaml"), []byte("project_name: my-project\n"), 0o600); err != nil {
		t.Fatalf("could not write the config: %+v", err)
	}

	_, err := FindDefaultCredentials(context.Background())

	// Off CBWS there is nothing left to try, and saying so is the right
	// answer. Naming the configuration file is not: nothing is wrong with
	// it.
	if err != nil && strings.Contains(err.Error(), "CBWS CLI config file") {
		t.Errorf("error = %v, want the lookup to move on to the next source", err)
	}
}

// TestFindDefaultCredentialsSkipsMissingConfig: likewise when there is no
// configuration file at all.
func TestFindDefaultCredentialsSkipsMissingConfig(t *testing.T) {
	isolate(t)

	_, err := FindDefaultCredentials(context.Background())

	if err != nil && strings.Contains(err.Error(), "CBWS CLI config file") {
		t.Errorf("error = %v, want the lookup to move on to the next source", err)
	}
}

// TestFindDefaultCredentialsReportsUnreadableConfig: a configuration that
// is broken rather than absent is worth stopping for, since silently
// authenticating as someone else would be worse than failing.
func TestFindDefaultCredentialsReportsUnreadableConfig(t *testing.T) {
	home := isolate(t)

	if err := os.WriteFile(filepath.Join(home, ".cbws.yaml"), []byte("oauth_token: [unclosed\n"), 0o600); err != nil {
		t.Fatalf("could not write the config: %+v", err)
	}

	_, err := FindDefaultCredentials(context.Background())
	if err == nil {
		t.Fatal("FindDefaultCredentials accepted a malformed configuration")
	}
	if !strings.Contains(err.Error(), "CBWS CLI config file") {
		t.Errorf("error = %v, want it to name the configuration file", err)
	}
}

// TestFindDefaultCredentialsPrefersTheEnvironment: an explicit key beats
// whatever the CLI happens to be logged in as, in both spellings of the
// variable.
func TestFindDefaultCredentialsPrefersTheEnvironment(t *testing.T) {
	for _, variable := range []string{"CBWS_CREDENTIALS", "CLOUDBEAR_CREDENTIALS"} {
		t.Run(variable, func(t *testing.T) {
			home := isolate(t)
			if err := os.WriteFile(filepath.Join(home, ".cbws.yaml"), []byte(tokenConfig), 0o600); err != nil {
				t.Fatalf("could not write the config: %+v", err)
			}

			t.Setenv(variable, writeServiceAccountKey(t, home))

			credentials, err := FindDefaultCredentials(context.Background())
			if err != nil {
				t.Fatalf("FindDefaultCredentials: %+v", err)
			}
			if credentials.TokenSource == nil {
				t.Fatal("credentials carry no token source")
			}
			if len(credentials.JSON) == 0 {
				t.Error("credentials carry no JSON, so the key was not the source used")
			}
		})
	}
}

// TestFindDefaultCredentialsPrefersCBWSCredentials: with both spellings set,
// CBWS_CREDENTIALS is used and the legacy one is not even read, so a stale
// legacy value cannot shadow it.
func TestFindDefaultCredentialsPrefersCBWSCredentials(t *testing.T) {
	home := isolate(t)
	t.Setenv("CBWS_CREDENTIALS", writeServiceAccountKey(t, home))
	t.Setenv("CLOUDBEAR_CREDENTIALS", filepath.Join(home, "absent.json"))

	credentials, err := FindDefaultCredentials(context.Background())
	if err != nil {
		t.Fatalf("FindDefaultCredentials: %+v", err)
	}
	if len(credentials.JSON) == 0 {
		t.Error("credentials carry no JSON, so the key was not the source used")
	}
}

// TestFindDefaultCredentialsReportsAMissingKey: a key named explicitly and
// not found is a mistake worth reporting, not a reason to fall back to
// another identity.
func TestFindDefaultCredentialsReportsAMissingKey(t *testing.T) {
	home := isolate(t)
	t.Setenv("CBWS_CREDENTIALS", filepath.Join(home, "absent.json"))

	_, err := FindDefaultCredentials(context.Background())
	if err == nil {
		t.Fatal("FindDefaultCredentials accepted a key that is not there")
	}
	if !strings.Contains(err.Error(), "CBWS_CREDENTIALS") {
		t.Errorf("error = %v, want it to name the variable that pointed at it", err)
	}
}

// TestFindDefaultCredentialsUsesTheWellKnownFile covers the key a developer
// drops in ~/.config/cbws rather than naming in the environment.
func TestFindDefaultCredentialsUsesTheWellKnownFile(t *testing.T) {
	home := isolate(t)

	dir := filepath.Join(home, ".config", "cbws")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %+v", err)
	}
	if err := os.Rename(writeServiceAccountKey(t, home), filepath.Join(dir, "credentials.json")); err != nil {
		t.Fatalf("Rename: %+v", err)
	}

	credentials, err := FindDefaultCredentials(context.Background())
	if err != nil {
		t.Fatalf("FindDefaultCredentials: %+v", err)
	}
	if len(credentials.JSON) == 0 {
		t.Error("credentials carry no JSON, so the well-known file was not used")
	}

	name, err := credentials.ProjectName(context.Background())
	if err != nil || name != "my-project" {
		t.Errorf("ProjectName() = %q, %v, want the key's project", name, err)
	}
}

// TestFindDefaultCredentialsAsksMetadataForTheProject: on a machine the
// project comes from the metadata server, and only once somebody asks.
func TestFindDefaultCredentialsAsksMetadataForTheProject(t *testing.T) {
	isolate(t)

	originalOnCBWS, originalSource, originalProject := onCBWS, metadataTokenSource, metadataProjectName
	t.Cleanup(func() {
		onCBWS, metadataTokenSource, metadataProjectName = originalOnCBWS, originalSource, originalProject
	})

	asked := 0
	onCBWS = func() bool { return true }
	metadataTokenSource = func(context.Context, []string) oauth2.TokenSource {
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "at"})
	}
	metadataProjectName = func(context.Context) (string, error) {
		asked++

		return "machine-project", nil
	}

	credentials, err := FindDefaultCredentials(context.Background())
	if err != nil {
		t.Fatalf("FindDefaultCredentials: %+v", err)
	}
	if asked != 0 {
		t.Errorf("finding credentials asked for the project %d times, want it left until needed", asked)
	}

	name, err := credentials.ProjectName(context.Background())
	if err != nil || name != "machine-project" {
		t.Errorf("ProjectName() = %q, %v, want the machine's project", name, err)
	}
}

// TestFindDefaultCredentialsPassesScopesToMetadata covers a workload on a
// machine, the last source tried. The scopes it asks for used to be dropped
// there, so the token it got carried none whatever it requested.
func TestFindDefaultCredentialsPassesScopesToMetadata(t *testing.T) {
	isolate(t)

	originalOnCBWS, originalSource := onCBWS, metadataTokenSource
	t.Cleanup(func() { onCBWS, metadataTokenSource = originalOnCBWS, originalSource })

	var requested []string
	onCBWS = func() bool { return true }
	metadataTokenSource = func(_ context.Context, scopes []string) oauth2.TokenSource {
		requested = scopes

		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "at"})
	}

	credentials, err := FindDefaultCredentials(context.Background(), "openid", "email")
	if err != nil {
		t.Fatalf("FindDefaultCredentials: %+v", err)
	}
	if credentials.TokenSource == nil {
		t.Fatal("credentials carry no token source")
	}
	if !slices.Equal(requested, []string{"openid", "email"}) {
		t.Errorf("metadata source requested %v, want [openid email]", requested)
	}
}

func TestNewFromJSON(t *testing.T) {
	t.Run("a service account key", func(t *testing.T) {
		data, err := os.ReadFile(writeServiceAccountKey(t, t.TempDir()))
		if err != nil {
			t.Fatalf("ReadFile: %+v", err)
		}

		credentials, err := NewFromJSON(context.Background(), data, []string{"openid"})
		if err != nil {
			t.Fatalf("NewFromJSON: %+v", err)
		}
		if credentials.TokenSource == nil {
			t.Error("credentials carry no token source")
		}

		name, err := credentials.ProjectName(context.Background())
		if err != nil || name != "my-project" {
			t.Errorf("ProjectName() = %q, %v, want the key's project", name, err)
		}
	})

	// Credentials built by hand, as callers outside this package do, have no
	// project lookup at all and must not panic for it.
	t.Run("a zero value", func(t *testing.T) {
		name, err := (&Credentials{}).ProjectName(context.Background())
		if err != nil || name != "" {
			t.Errorf("ProjectName() = %q, %v, want no project", name, err)
		}
	})

	t.Run("not JSON at all", func(t *testing.T) {
		_, err := NewFromJSON(context.Background(), []byte("{"), nil)
		if err == nil {
			t.Error("NewFromJSON accepted something that is not JSON")
		}
	})

	// A key that cannot be read has to be an error rather than credentials
	// carrying a nil token source, which a caller cannot tell from success
	// and only finds out about when the first request dereferences it.
	t.Run("a key whose private key is not a key", func(t *testing.T) {
		data, err := json.Marshal(map[string]string{
			"type":         "service_account",
			"client_id":    "some-client",
			"client_email": "sa@my-project.example",
			"private_key":  "not a PEM block",
		})
		if err != nil {
			t.Fatalf("Marshal: %+v", err)
		}

		credentials, err := NewFromJSON(context.Background(), data, nil)
		if err == nil {
			t.Fatalf("NewFromJSON accepted an unusable key, returning %+v", credentials)
		}
		if !strings.Contains(err.Error(), "private key") {
			t.Errorf("error = %v, want it to say the private key could not be read", err)
		}
	})
}

// writeServiceAccountKey generates a usable service account key file and
// returns its path. The key is generated rather than checked in so the
// repository holds no PEM-shaped material at all.
func writeServiceAccountKey(t *testing.T, dir string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %+v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %+v", err)
	}

	data, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_name":   "my-project",
		"private_key_id": "key-1",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   "sa@my-project.example",
		"client_id":      "sa-client-id",
	})
	if err != nil {
		t.Fatalf("Marshal: %+v", err)
	}

	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %+v", err)
	}

	return path
}

// TestFindsTheConfigurationTheCLIWrites is the regression for a lookup
// that never found one. The CLI writes a dotfile and this package looked
// for the undotted name, so unless CBWS_CONFIG_FILE was set the CLI
// credential was skipped on every machine: an SDK tool could not pick up
// whoever had run `cbws init`, which is the whole point of that step.
//
// The candidates are tried in order rather than chosen between, so a
// dotfile holding no credential does not stop the older name being read.
func TestFindsTheConfigurationTheCLIWrites(t *testing.T) {
	tokenless := "project_name: my-project\n"
	dotted := configHolding("at-dotted")
	undotted := configHolding("at-undotted")

	for _, test := range []struct {
		name  string
		write map[string]string
		want  string
	}{
		{
			name:  "the dotfile the CLI writes",
			write: map[string]string{".cbws.yaml": dotted},
			want:  "at-dotted",
		},
		{
			// Kept working rather than dropped, for a machine that
			// somehow has one.
			name:  "the undotted name this package used to look for",
			write: map[string]string{"cbws.yaml": undotted},
			want:  "at-undotted",
		},
		{
			name:  "both, and the CLI's own wins",
			write: map[string]string{".cbws.yaml": dotted, "cbws.yaml": undotted},
			want:  "at-dotted",
		},
		{
			// The case that makes this an ordered list rather than a
			// choice: a configuration holding a project name and no
			// credential must not stop the next candidate being read.
			name:  "a tokenless dotfile does not shadow the older name",
			write: map[string]string{".cbws.yaml": tokenless, "cbws.yaml": undotted},
			want:  "at-undotted",
		},
		{
			name:  "a dotfile that is not a file does not shadow it either",
			write: map[string]string{"cbws.yaml": undotted},
			want:  "at-undotted",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := isolate(t)

			// The override is what used to be the only way here, so it is
			// cleared to exercise the default.
			t.Setenv("CBWS_CONFIG_FILE", "")

			for name, content := range test.write {
				if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
					t.Fatalf("could not write %s: %+v", name, err)
				}
			}

			if test.name == "a dotfile that is not a file does not shadow it either" {
				if err := os.Mkdir(filepath.Join(home, ".cbws.yaml"), 0o700); err != nil {
					t.Fatalf("Mkdir: %+v", err)
				}
			}

			credentials, err := FindDefaultCredentialsWithOptions(context.Background(), nil)
			if err != nil {
				t.Fatalf("FindDefaultCredentials: %+v", err)
			}

			assertServes(t, credentials, test.want)
		})
	}
}

// configHolding is a CLI configuration whose access token is still valid,
// so a source built from it answers without going anywhere. Which token
// comes back is how a test tells which file was read.
func configHolding(accessToken string) string {
	return "project_name: my-project\noauth_token:\n" +
		"    accesstoken: " + accessToken + "\n" +
		"    tokentype: bearer\n" +
		"    refreshtoken: rt-0\n" +
		"    expiry: 2199-01-01T00:00:00Z\n"
}

// assertServes checks which configuration a credential came out of, by the
// token it hands over.
func assertServes(t *testing.T, credentials *Credentials, want string) {
	t.Helper()

	token, err := credentials.TokenSource.Token()
	if err != nil {
		t.Fatalf("Token: %+v", err)
	}
	if token.AccessToken != want {
		t.Errorf("served %q, want %q", token.AccessToken, want)
	}
}

// TestTheOverrideStillWins: CBWS_CONFIG_FILE has been the only way this
// lookup ever reached a CLI credential, so whatever else changes, it keeps
// working.
func TestTheOverrideStillWins(t *testing.T) {
	home := isolate(t)

	// A dotfile in the home directory that must not be preferred over the
	// one named explicitly.
	if err := os.WriteFile(filepath.Join(home, ".cbws.yaml"), []byte(configHolding("at-dotted")), 0o600); err != nil {
		t.Fatalf("WriteFile: %+v", err)
	}

	elsewhere := filepath.Join(t.TempDir(), "named.yaml")
	if err := os.WriteFile(elsewhere, []byte(configHolding("at-named")), 0o600); err != nil {
		t.Fatalf("WriteFile: %+v", err)
	}
	t.Setenv("CBWS_CONFIG_FILE", elsewhere)

	credentials, err := FindDefaultCredentialsWithOptions(context.Background(), nil)
	if err != nil {
		t.Fatalf("FindDefaultCredentials: %+v", err)
	}

	assertServes(t, credentials, "at-named")

	// And nothing else is considered: naming one configuration and having
	// another read instead would answer a different question.
	if got := cliConfigFiles(); len(got) != 1 || got[0] != elsewhere {
		t.Errorf("candidates = %v, want only the named file", got)
	}
}

// TestAConfigurationThatIsNotAFile: a directory or a FIFO named like the
// configuration is an absent configuration rather than a broken one. The
// difference matters: reported as broken it fails the whole lookup, and a
// FIFO read would not return at all.
func TestAConfigurationThatIsNotAFile(t *testing.T) {
	for _, name := range []string{".cbws.yaml", "cbws.yaml"} {
		t.Run(name+" as a directory", func(t *testing.T) {
			home := isolate(t)
			t.Setenv("CBWS_CONFIG_FILE", "")

			if err := os.Mkdir(filepath.Join(home, name), 0o700); err != nil {
				t.Fatalf("Mkdir: %+v", err)
			}

			// Nothing else to find, so the lookup runs out rather than
			// failing on the directory.
			_, err := FindDefaultCredentialsWithOptions(context.Background(), nil)
			if err != nil && strings.Contains(err.Error(), "CBWS CLI config file") {
				t.Errorf("error = %v, want the directory stepped over", err)
			}
		})
	}
}

// TestAnExplicitConfigurationIsNotAuthoritative documents what happens when
// CBWS_CONFIG_FILE names a configuration that is not there or holds no
// credential: the lookup carries on to the next source rather than
// stopping.
//
// That is not the same as the service account variables, which fail when
// the file they name is missing, and it means a configuration that has gone
// astray can be answered by the machine's own identity instead. It is long
// standing behaviour and changing it is its own decision, so it is pinned
// here rather than left to be discovered.
func TestAnExplicitConfigurationIsNotAuthoritative(t *testing.T) {
	for _, test := range []struct {
		name  string
		write string
	}{
		{name: "missing"},
		{name: "holding no credential", write: "project_name: my-project\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := isolate(t)

			named := filepath.Join(home, "named.yaml")
			if test.write != "" {
				if err := os.WriteFile(named, []byte(test.write), 0o600); err != nil {
					t.Fatalf("WriteFile: %+v", err)
				}
			}
			t.Setenv("CBWS_CONFIG_FILE", named)

			_, err := FindDefaultCredentialsWithOptions(context.Background(), nil)
			if err != nil && strings.Contains(err.Error(), "CBWS CLI config file") {
				t.Errorf("error = %v, want the lookup to have carried on", err)
			}
		})
	}
}

// TestAMalformedConfigurationStopsTheLookup: a configuration that is there
// and cannot be read is not a reason to go looking for another identity.
func TestAMalformedConfigurationStopsTheLookup(t *testing.T) {
	home := isolate(t)
	t.Setenv("CBWS_CONFIG_FILE", "")

	if err := os.WriteFile(filepath.Join(home, ".cbws.yaml"), []byte("oauth_token: [unclosed\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %+v", err)
	}
	// A perfectly good one behind it, which must not be reached.
	if err := os.WriteFile(filepath.Join(home, "cbws.yaml"), []byte(tokenConfig), 0o600); err != nil {
		t.Fatalf("WriteFile: %+v", err)
	}

	_, err := FindDefaultCredentialsWithOptions(context.Background(), nil)
	if err == nil {
		t.Fatal("a malformed configuration was stepped over")
	}
	if !strings.Contains(err.Error(), "CBWS CLI config file") {
		t.Errorf("error = %v, want it to name the configuration", err)
	}
}

// TestAConfigurationThatCannotBeLookedAtStopsTheLookup: not being there is
// an answer and the lookup moves on. Not being able to tell is not, and
// reading it as one would step over a configuration that may hold a
// credential and go on to authenticate as the machine.
func TestAConfigurationThatCannotBeLookedAtStopsTheLookup(t *testing.T) {
	// A symlink loop: something is at the path, and no amount of looking
	// says what.
	looping := func(t *testing.T, dir string) string {
		t.Helper()

		path := filepath.Join(dir, "looping.yaml")
		if err := os.Symlink(path, path); err != nil {
			t.Fatalf("Symlink: %+v", err)
		}

		return path
	}

	t.Run("named explicitly", func(t *testing.T) {
		home := isolate(t)
		t.Setenv("CBWS_CONFIG_FILE", looping(t, home))

		_, err := FindDefaultCredentialsWithOptions(context.Background(), nil)
		if err == nil {
			t.Fatal("a configuration that could not be looked at was stepped over")
		}
		if !strings.Contains(err.Error(), "CBWS CLI config file") {
			t.Errorf("error = %v, want it to name the configuration", err)
		}
	})

	t.Run("found by default", func(t *testing.T) {
		home := isolate(t)
		t.Setenv("CBWS_CONFIG_FILE", "")

		path := filepath.Join(home, ".cbws.yaml")
		if err := os.Symlink(path, path); err != nil {
			t.Fatalf("Symlink: %+v", err)
		}

		// A perfectly good one behind it, which must not be reached: the
		// first candidate might have been the one that mattered.
		if err := os.WriteFile(filepath.Join(home, "cbws.yaml"), []byte(configHolding("at-undotted")), 0o600); err != nil {
			t.Fatalf("WriteFile: %+v", err)
		}

		_, err := FindDefaultCredentialsWithOptions(context.Background(), nil)
		if err == nil {
			t.Fatal("a configuration that could not be looked at was stepped over")
		}
	})
}

// TestIsFileTellsAbsenceFromNotKnowing is the distinction the lookup rests
// on, stated on its own.
func TestIsFileTellsAbsenceFromNotKnowing(t *testing.T) {
	dir := t.TempDir()

	regular := filepath.Join(dir, "regular.yaml")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %+v", err)
	}

	directory := filepath.Join(dir, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir: %+v", err)
	}

	looping := filepath.Join(dir, "looping")
	if err := os.Symlink(looping, looping); err != nil {
		t.Fatalf("Symlink: %+v", err)
	}

	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "gone"), dangling); err != nil {
		t.Fatalf("Symlink: %+v", err)
	}

	for _, test := range []struct {
		name    string
		path    string
		want    bool
		wantErr bool
	}{
		{name: "a regular file", path: regular, want: true},
		{name: "nothing there", path: filepath.Join(dir, "absent.yaml")},
		{name: "a directory", path: directory},
		{name: "a symlink loop", path: looping, wantErr: true},
		{name: "a symlink to nothing", path: dangling, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := isFile(test.path)

			if test.wantErr {
				if err == nil {
					t.Fatal("no error for a path that could not be looked at")
				}

				return
			}

			if err != nil {
				t.Fatalf("isFile: %+v", err)
			}
			if got != test.want {
				t.Errorf("isFile = %v, want %v", got, test.want)
			}
		})
	}
}
