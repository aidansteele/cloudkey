# cloudkey admin api

```go
package main

import "time"

// GET /identities?nextToken=$NextToken
type ListIdentitiesInput struct {
	NextToken string
}

type ListIdentitiesOutput struct {
	Identities []struct {
		IdentityName      string
		CertificateExpiry time.Time
		RoleNames         []string
	}
	NextToken string // empty on last page
}

// PUT /identities/$IdentityName
type PutIdentityInput struct {
	IdentityName                 string
	CertificateSigningRequestPEM string
}

type PutIdentityOutput struct {
	CertificateId string
}

// PUT /identities/$IdentityName/roles
type PutIdentityAttachedRolesInput struct {
	IdentityName string
	RoleNames    string
}

type PutIdentityAttachedRolesOutput struct {
	PolicyVersionId string
}

// DELETE /identities/$IdentityName
type DeleteIdentityInput struct {
	IdentityName string
}

type DeleteIdentityOutput struct {
	StatusToken string
}
```