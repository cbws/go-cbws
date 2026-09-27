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
	"strings"
	"testing"
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
