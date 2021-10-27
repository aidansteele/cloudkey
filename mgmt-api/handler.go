package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iot"
	"github.com/aws/aws-sdk-go/service/iot/iotiface"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"strings"
	"sync"
)

type handler struct {
	iot iotiface.IoTAPI
}

func (h *handler) ListIdentities(ctx context.Context, input *ListIdentitiesInput) (*ListIdentitiesOutput, error) {
	var nextToken *string
	if input.NextToken != "" {
		nextToken = &input.NextToken
	}

	listThings, err := h.iot.ListThingsWithContext(ctx, &iot.ListThingsInput{
		AttributeName:  aws.String("cloudkey"),
		AttributeValue: aws.String("cloudkey"),
		NextToken:      nextToken,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	identities := []*ListedIdentity{}

	// TODO: stop after a timeout (e.g. 5 secs) and return what we have so far + pagination token
	for _, thing := range listThings.Things {
		certificateArns := []string{}

		identity := &ListedIdentity{IdentityName: *thing.ThingName}
		identities = append(identities, identity)

		err = h.iot.ListThingPrincipalsPagesWithContext(ctx, &iot.ListThingPrincipalsInput{ThingName: thing.ThingName}, func(page *iot.ListThingPrincipalsOutput, lastPage bool) bool {
			certificateArns = append(certificateArns, aws.StringValueSlice(page.Principals)...)
			return !lastPage
		})
		if err != nil {
			return nil, errors.WithStack(err)
		}

		if len(certificateArns) != 1 {
			return nil, errors.New("unexpected number of certificates associated with thing") // TODO
		}

		for _, arn := range certificateArns {
			id := strings.TrimPrefix(arn, "") // TODO
			describeCertificate, err := h.iot.DescribeCertificateWithContext(ctx, &iot.DescribeCertificateInput{CertificateId: &id})
			if err != nil {
				return nil, errors.WithStack(err)
			}

			identity.CertificateExpiry = *describeCertificate.CertificateDescription.Validity.NotAfter

			policyNames := []string{}
			err = h.iot.ListPrincipalPoliciesPagesWithContext(ctx, &iot.ListPrincipalPoliciesInput{Principal: &arn}, func(page *iot.ListPrincipalPoliciesOutput, lastPage bool) bool {
				for _, policy := range page.Policies {
					policyNames = append(policyNames, *policy.PolicyName)
				}
				return !lastPage
			})
			if err != nil {
				return nil, errors.WithStack(err)
			}

			if len(policyNames) != 1 {
				return nil, errors.New("unexpected number of policies associated with certificate") // TODO
			}

			for _, policyName := range policyNames {
				getPolicy, err := h.iot.GetPolicyWithContext(ctx, &iot.GetPolicyInput{PolicyName: &policyName})
				if err != nil {
					return nil, errors.WithStack(err)
				}

				getPolicyVersion, err := h.iot.GetPolicyVersionWithContext(ctx, &iot.GetPolicyVersionInput{
					PolicyName:      &policyName,
					PolicyVersionId: getPolicy.DefaultVersionId,
				})
				if err != nil {
					return nil, errors.WithStack(err)
				}

				doc := policyDocument{}
				err = json.Unmarshal([]byte(*getPolicyVersion.PolicyDocument), &doc)
				if err != nil {
					return nil, errors.WithStack(err)
				}

				if len(doc.Statement) != 1 {
					return nil, errors.New("unexpected number of statements in policy document")
				}

				stmt := doc.Statement[0]
				if stmt.Effect != "Allow" || stmt.Action != "iot:AssumeRoleWithCertificate" {
					return nil, errors.New("unexpected effect or action in policy statement")
				}

				for _, roleAliasArn := range stmt.Resource {
					identity.RoleNames = append(identity.RoleNames, strings.TrimPrefix(roleAliasArn, "TODO")) // TODO: prefix
				}
			}
		}
	}

	return &ListIdentitiesOutput{
		Identities: identities,
		NextToken:  "", // TODO: nexttoken
	}, nil
}

func (h *handler) PutIdentity(ctx context.Context, input *PutIdentityInput) (*PutIdentityOutput, error) {
	_, err := h.iot.CreateThingWithContext(ctx, &iot.CreateThingInput{
		ThingName: &input.IdentityName,
		AttributePayload: &iot.AttributePayload{
			Merge: nil,
			Attributes: map[string]*string{
				"cloudkey": aws.String("cloudkey"),
			},
		},
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	createCertificate, err := h.iot.CreateCertificateFromCsrWithContext(ctx, &iot.CreateCertificateFromCsrInput{
		CertificateSigningRequest: &input.CertificateSigningRequestPEM,
		SetAsActive:               aws.Bool(true),
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	_, err = h.iot.AttachThingPrincipalWithContext(ctx, &iot.AttachThingPrincipalInput{
		ThingName: &input.IdentityName,
		Principal: createCertificate.CertificateArn,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	_, err = h.iot.CreatePolicyWithContext(ctx, &iot.CreatePolicyInput{
		PolicyName:     &input.IdentityName,
		PolicyDocument: nil,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	_, err = h.iot.AttachPolicyWithContext(ctx, &iot.AttachPolicyInput{
		PolicyName: &input.IdentityName,
		Target:     createCertificate.CertificateArn,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &PutIdentityOutput{
		CertificateId: *createCertificate.CertificateId,
	}, nil
}

type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect   string   `json:"Effect"`
	Action   string   `json:"Action"`
	Resource []string `json:"Resource"`
}

func (h *handler) PutIdentityAttachedRoles(ctx context.Context, input *PutIdentityAttachedRolesInput) (*PutIdentityAttachedRolesOutput, error) {
	getPolicy, err := h.iot.GetPolicyWithContext(ctx, &iot.GetPolicyInput{
		PolicyName: &input.IdentityName,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	accountId := "TODO" // TODO
	roleAliasArns := []string{}
	mut := sync.Mutex{}

	g, gctx := errgroup.WithContext(ctx)
	for _, roleName := range input.RoleNames {
		roleName := roleName
		g.Go(func() error {
			createRoleAlias, err := h.iot.CreateRoleAliasWithContext(gctx, &iot.CreateRoleAliasInput{
				RoleAlias: &roleName,
				RoleArn:   aws.String(fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, roleName)),
			})
			if err != nil {
				return errors.WithStack(err)
			}

			mut.Lock()
			roleAliasArns = append(roleAliasArns, *createRoleAlias.RoleAliasArn)
			mut.Unlock()
			return nil
		})
	}

	err = g.Wait()
	if err != nil {
		return nil, err
	}

	docJson, _ := json.Marshal(policyDocument{
		Version: "2012-10-17",
		Statement: []policyStatement{
			{
				Effect:   "Allow",
				Action:   "iot:AssumeRoleWithCertificate",
				Resource: roleAliasArns,
			},
		},
	})

	createPolicyVersion, err := h.iot.CreatePolicyVersionWithContext(ctx, &iot.CreatePolicyVersionInput{
		PolicyName:     &input.IdentityName,
		SetAsDefault:   aws.Bool(true),
		PolicyDocument: aws.String(string(docJson)),
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	_, err = h.iot.DeletePolicyVersionWithContext(ctx, &iot.DeletePolicyVersionInput{
		PolicyName:      &input.IdentityName,
		PolicyVersionId: getPolicy.DefaultVersionId,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &PutIdentityAttachedRolesOutput{
		PolicyVersionId: *createPolicyVersion.PolicyVersionId,
	}, nil
}

func (h *handler) DeleteIdentity(ctx context.Context, input *DeleteIdentityInput) (*DeleteIdentityOutput, error) {
	// TODO: start a sfn execution to do this. docs say things can
	// take seconds to minutes after detachment before deletion
	panic("implement me")
}
