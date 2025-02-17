# CBWS SDK for Go

Go clients for the CBWS cloud platform APIs.

```bash
go get go.cbws.cloud/sdk
```

## Packages

- `go.cbws.cloud/sdk/cbws/compute/v1alpha1`: machines, machine types and images
- `go.cbws.cloud/sdk/cbws/vpc/v1alpha1`: VPCs and private networks
- `go.cbws.cloud/sdk/cbws/projects/v1alpha1`: projects and their IAM policies
- `go.cbws.cloud/sdk/cbws/iam/v1alpha1`: service account keys and access tokens
- `go.cbws.cloud/sdk/cbws/service_usage/v1alpha1`: the services of a project
- `go.cbws.cloud/sdk/cbws/longrunning/v1alpha1`: waiting for long-running operations

The clients wrap the generated gRPC code of `go.cbws.cloud/api`. Each client also gives access to
the underlying generated client.

## Authentication

See [docs/authentication.md](docs/authentication.md).
