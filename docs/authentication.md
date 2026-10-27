# CBWS Go SDK Authentication

The CBWS Go SDK provides a robust and flexible authentication mechanism that automatically discovers credentials from various sources, ensuring seamless integration whether running locally, in a CI/CD pipeline, or directly on CBWS infrastructure.

The SDK checks for credentials in the following order:

1.  **Environment Variable (`CBWS_CREDENTIALS`)**
    The SDK first looks for the **path to a credentials file** in the `CBWS_CREDENTIALS` environment variable. The variable holds a filename, not the credentials themselves: the value is passed straight to `ReadFile`, so a variable containing inline JSON fails with `open {"type": "service_account"...}: no such file or directory`. This method is often used in containerized environments and CI/CD pipelines, where the credentials are mounted or written to a file and only the path is injected.

    Example:
    ```bash
    export CBWS_CREDENTIALS=/etc/cbws/credentials.json
    ```

    The file it points at holds the service account key as JSON, in the same format as the well-known file described below.

    **In CI/CD**, use whatever your runner offers for file-backed secrets rather than pasting the key into a plain variable. In GitLab CI, set the variable's type to **File**: GitLab then writes the value to a temporary file and sets `CBWS_CREDENTIALS` to that path. A variable of type *Variable* holding the JSON will not work.

    **Legacy:** `CLOUDBEAR_CREDENTIALS` is deprecated. It behaves identically, but the SDK reads it only when `CBWS_CREDENTIALS` is not set.

2.  **Well-Known Credentials File (`~/.config/cbws/credentials.json`)**
    If the `CBWS_CREDENTIALS` environment variable is not set, the SDK then checks for a credentials file at the standard location: `~/.config/cbws/credentials.json`. This file should contain a JSON object with your CBWS service account credentials. This is a common method for local development environments.

    Example `credentials.json` content:
    ```json
    {
      "type": "service_account",
      "project_name": "YOUR_PROJECT_NAME",
      "private_key_id": "YOUR_PRIVATE_KEY_ID",
      "private_key": "-----BEGIN PRIVATE KEY-----
YOUR_PRIVATE_KEY_CONTENT
-----END PRIVATE KEY-----
",
      "client_email": "YOUR_SERVICE_ACCOUNT_EMAIL",
      "client_id": "YOUR_CLIENT_ID"
    }
    ```

3.  **`cbws-cli` Configuration File (`~/cbws.yaml`)**
    Next, the SDK attempts to load credentials from the `cbws-cli` configuration file, at `~/cbws.yaml` unless `CBWS_CONFIG_FILE` points somewhere else. This allows the SDK to leverage credentials already configured for the CBWS Command-Line Interface. Refer to the `cbws-cli` documentation for details on how to configure credentials via the CLI.

4.  **CBWS Metadata Service**
    Finally, if no credentials are found through the above methods, the SDK will attempt to authenticate using the CBWS metadata service. This method is automatically used when your application is running on CBWS infrastructure (e.g., on a CBWS Virtual Machine or a service deployed within the CBWS platform). It allows for secure and automatic authentication without the need to explicitly manage credentials in your application code or environment.

### Token Endpoint for Service Account Keys (`CBWS_TOKEN_URL`)

A service account key is exchanged for an access token at `https://accounts.cbws.cloud/oauth2/token`. Setting `CBWS_TOKEN_URL` sends that exchange to another address instead, which lets a workload inside the CBWS platform reach the token service directly rather than through the public internet gateway:

```bash
export CBWS_TOKEN_URL=http://accounts-hydra-public.core-accounts-hydra.svc.cluster.local.:4444/oauth2/token
```

Only the address changes. The signed assertion is still addressed to the public token URL, and the token that comes back is issued by `https://accounts.cbws.cloud`, so a token obtained either way is the same. The variable applies to service account keys only: CLI logins and the metadata service keep their own endpoints. A program that calls `service_account.SetTokenURL` overrides it.

### User-Managed vs. Platform-Managed Service Account Keys: Security Considerations

The CBWS platform provides two primary ways to manage service account authentication, each with distinct security implications:

*   **User-Managed Keys:** These are the service account keys (typically in JSON file format) that you explicitly create and manage. When you use environment variables or a well-known credentials file, you are employing user-managed keys. With these keys, you are directly responsible for:
    *   **Secure Storage:** Ensuring the private key material is stored in a secure location and protected from unauthorized access.
    *   **Key Rotation:** Regularly rotating your keys to minimize the impact of a compromised key.
    User-managed keys offer flexibility but place the burden of security on your operational practices.

*   **Platform-Managed Keys (via Metadata Service):** When you leverage the CBWS Metadata Service for authentication, you are using platform-managed keys. These keys and their associated credentials are:
    *   **Automatically Managed:** Created, stored, and rotated securely by the CBWS platform. The sensitive private key material is never exposed directly to your application or environment.
    *   **Short-Lived & Ephemeral:** The metadata service vends short-lived access tokens, significantly reducing the window of opportunity for compromise if a token is inadvertently exposed.
    *   **Context-Aware:** Authentication is tied to the secure execution environment (e.g., a specific VM or service), providing a strong identity without requiring explicit credential files within your application.
    The Metadata Service approach significantly enhances security by eliminating the need for users to store or rotate sensitive key material themselves, thereby reducing the risk of accidental exposure or compromise. This is generally the recommended approach for applications running within the CBWS ecosystem.

### Explicit Credential Provisioning

While the SDK provides automatic credential discovery, you can also explicitly provide credentials when initializing a client using `option.WithCredentialsFile` or `option.WithTokenSource`.

Example with `option.WithCredentialsFile`:

```go
package main

import (
	"context"
	"log"

	"go.cbws.cloud/sdk/cbws/compute/v1alpha1"
	"go.cbws.cloud/sdk/option"
)

func main() {
	ctx := context.Background()

	// Provide credentials explicitly from a file
	computeClient, err := compute.NewClient(ctx, "your-cbws-project-id", option.WithCredentialsFile("/path/to/your/custom_credentials.json"))
	if err != nil {
		log.Fatalf("Failed to create compute client: %v", err)
	}

	// Use computeClient...
}
```
