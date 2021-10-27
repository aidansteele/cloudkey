package main

import (
	"context"
	"time"
)

type Handler interface {
	ListIdentities(ctx context.Context, input *ListIdentitiesInput) (*ListIdentitiesOutput, error)
	PutIdentity(ctx context.Context, input *PutIdentityInput) (*PutIdentityOutput, error)
	PutIdentityAttachedRoles(ctx context.Context, input *PutIdentityAttachedRolesInput) (*PutIdentityAttachedRolesOutput, error)
	DeleteIdentity(ctx context.Context, input *DeleteIdentityInput) (*DeleteIdentityOutput, error)
}

type ListIdentitiesInput struct {
	NextToken string
}

type ListedIdentity struct {
	IdentityName      string
	CertificateExpiry time.Time
	RoleNames         []string
}

type ListIdentitiesOutput struct {
	Identities []*ListedIdentity
	NextToken  string // empty on last page
}

type PutIdentityInput struct {
	IdentityName                 string
	CertificateSigningRequestPEM string
}

type PutIdentityOutput struct {
	CertificateId string
}

type DeleteIdentityInput struct {
	IdentityName string
}

type DeleteIdentityOutput struct {
	StatusToken string
}

type PutIdentityAttachedRolesInput struct {
	IdentityName string
	RoleNames    []string
}

type PutIdentityAttachedRolesOutput struct {
	PolicyVersionId string
}
