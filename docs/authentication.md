# CBWS Go SDK Authentication

The CBWS Go SDK provides a robust and flexible authentication mechanism that automatically discovers credentials from various sources, ensuring seamless integration whether running locally, in a CI/CD pipeline, or directly on CBWS infrastructure.

The SDK checks for credentials in the following order:

1.  **Environment Variables (`CBWS_CREDENTIALS`)**
    The SDK first looks for credentials provided directly through the `CBWS_CREDENTIALS` environment variable. This variable should contain a JSON string representing your CBWS service account credentials. This method is often used in containerized environments or CI/CD pipelines where injecting credentials via environment variables is convenient and secure.

    Example:
    ```bash
    export CBWS_CREDENTIALS='{
      "type": "service_account",
      "project_name": "YOUR_PROJECT_NAME",
      "private_key_id": "YOUR_PRIVATE_KEY_ID",
      "private_key": "-----BEGIN PRIVATE KEY-----
YOUR_PRIVATE_KEY_CONTENT
-----END PRIVATE KEY-----
",
      "client_email": "YOUR_SERVICE_ACCOUNT_EMAIL",
      "client_id": "YOUR_CLIENT_ID"
    }'
    ```

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
    Next, the SDK attempts to load credentials from the `cbws-cli` configuration file, typically located at `~/cbws.yaml`. This allows the SDK to leverage credentials already configured for the CBWS Command-Line Interface. Refer to the `cbws-cli` documentation for details on how to configure credentials via the CLI.

4.  **CBWS Metadata Service**
    Finally, if no credentials are found through the above methods, the SDK will attempt to authenticate using the CBWS metadata service. This method is automatically used when your application is running on CBWS infrastructure (e.g., on a CBWS Virtual Machine or a service deployed within the CBWS platform). It allows for secure and automatic authentication without the need to explicitly manage credentials in your application code or environment.

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
