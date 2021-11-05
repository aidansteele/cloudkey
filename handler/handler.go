package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/aidansteele/cloudkey/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/iot"
	"github.com/aws/aws-sdk-go/service/iot/iotiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"strings"
	"sync"
)

type Handler struct {
	iot       iotiface.IoTAPI
	region    string
	accountId string
	endpoint  string
}

var _ types.Handler = &Handler{}

func New(cfgp client.ConfigProvider) *Handler {
	gci, err := sts.New(cfgp).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	h := &Handler{
		iot:       iot.New(cfgp),
		region:    cfgp.ClientConfig("iot").SigningRegion,
		accountId: *gci.Account,
	}

	endpoint, err := h.iot.DescribeEndpoint(&iot.DescribeEndpointInput{EndpointType: aws.String("iot:CredentialProvider")})
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	h.endpoint = *endpoint.EndpointAddress

	return h
}

func (h *Handler) Endpoint() string {
	return h.endpoint
}

func (h *Handler) ListIdentities(ctx context.Context, input *types.ListIdentitiesInput) (*types.ListIdentitiesOutput, error) {
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

	identities := []*types.ListedIdentity{}

	// TODO: stop after a timeout (e.g. 5 secs) and return what we have so far + pagination token
	for _, thing := range listThings.Things {
		certificateArns := []string{}

		identity := &types.ListedIdentity{IdentityName: *thing.ThingName}
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
			certificateArnPrefix := fmt.Sprintf("arn:aws:iot:%s:%s:cert/", h.region, h.accountId)
			certificateId := strings.TrimPrefix(arn, certificateArnPrefix)

			describeCertificate, err := h.iot.DescribeCertificateWithContext(ctx, &iot.DescribeCertificateInput{CertificateId: &certificateId})
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
				if stmt.Action != "iot:AssumeRoleWithCertificate" {
					return nil, errors.New("unexpected effect or action in policy statement")
				}

				for _, roleAliasArn := range stmt.Resource {
					roleAliasArnPrefix := fmt.Sprintf("arn:aws:iot:%s:%s:rolealias/", h.region, h.accountId)
					identity.RoleNames = append(identity.RoleNames, strings.TrimPrefix(roleAliasArn, roleAliasArnPrefix))
				}
			}
		}
	}

	return &types.ListIdentitiesOutput{
		Identities: identities,
		NextToken:  "", // TODO: nexttoken
	}, nil
}

func (h *Handler) PutIdentity(ctx context.Context, input *types.PutIdentityInput) (*types.PutIdentityOutput, error) {
	csrPem := &bytes.Buffer{}
	err := pem.Encode(csrPem, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: input.CertificateRequestDER,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	createCertificate, err := h.iot.CreateCertificateFromCsrWithContext(ctx, &iot.CreateCertificateFromCsrInput{
		CertificateSigningRequest: aws.String(csrPem.String()),
		SetAsActive:               aws.Bool(true),
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	_, err = h.iot.CreateThingWithContext(ctx, &iot.CreateThingInput{
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

	_, err = h.iot.AttachThingPrincipalWithContext(ctx, &iot.AttachThingPrincipalInput{
		ThingName: &input.IdentityName,
		Principal: createCertificate.CertificateArn,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	docJson, _ := json.Marshal(policyDocument{
		Version: "2012-10-17",
		Statement: []policyStatement{
			{
				Effect:   "Deny",
				Action:   "iot:AssumeRoleWithCertificate",
				Resource: []string{"*"},
			},
		},
	})

	_, err = h.iot.CreatePolicyWithContext(ctx, &iot.CreatePolicyInput{
		PolicyName:     &input.IdentityName,
		PolicyDocument: aws.String(string(docJson)),
	})
	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == iot.ErrCodeResourceAlreadyExistsException {
		// no-op
	} else if err != nil {
		return nil, errors.WithStack(err)
	}

	_, err = h.iot.AttachPolicyWithContext(ctx, &iot.AttachPolicyInput{
		PolicyName: &input.IdentityName,
		Target:     createCertificate.CertificateArn,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	block, _ := pem.Decode([]byte(*createCertificate.CertificatePem))

	return &types.PutIdentityOutput{
		CertificateId:  *createCertificate.CertificateId,
		CertificateDER: block.Bytes,
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

func (h *Handler) PutIdentityAttachedRoles(ctx context.Context, input *types.PutIdentityAttachedRolesInput) (*types.PutIdentityAttachedRolesOutput, error) {
	getPolicy, err := h.iot.GetPolicyWithContext(ctx, &iot.GetPolicyInput{
		PolicyName: &input.IdentityName,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	roleAliasArns := []string{}
	mut := sync.Mutex{}

	g, gctx := errgroup.WithContext(ctx)
	for _, roleName := range input.RoleNames {
		roleName := roleName
		g.Go(func() error {
			_, err := h.iot.CreateRoleAliasWithContext(gctx, &iot.CreateRoleAliasInput{
				RoleAlias: &roleName,
				RoleArn:   aws.String(fmt.Sprintf("arn:aws:iam::%s:role/%s", h.accountId, roleName)),
			})
			if err != nil {
				if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == iot.ErrCodeResourceAlreadyExistsException {
					// do nothing
				} else {
					return errors.WithStack(err)
				}
			}

			mut.Lock()
			// note: we don't use response from api in case it already exists (and therefore is empty)
			roleAliasArn := fmt.Sprintf("arn:aws:iot:%s:%s:rolealias/%s", h.region, h.accountId, roleName)
			roleAliasArns = append(roleAliasArns, roleAliasArn)
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

	return &types.PutIdentityAttachedRolesOutput{
		PolicyVersionId: *createPolicyVersion.PolicyVersionId,
	}, nil
}

func (h *Handler) DeleteIdentity(ctx context.Context, input *types.DeleteIdentityInput) (*types.DeleteIdentityOutput, error) {
	// TODO: start a sfn execution to do this. docs say things can
	// take seconds to minutes after detachment before deletion
	err := h.DeleteIdentitySync(ctx, input)
	if err != nil {
		return nil, err
	}

	return &types.DeleteIdentityOutput{StatusToken: "TODO"}, nil
}

func (h *Handler) DeleteIdentitySync(ctx context.Context, input *types.DeleteIdentityInput) error {
	thingName := &input.IdentityName

	certificateIds := []string{}
	certificateArnPrefix := fmt.Sprintf("arn:aws:iot:%s:%s:cert/", h.region, h.accountId)

	var innerErr error
	err := h.iot.ListThingPrincipalsPagesWithContext(ctx, &iot.ListThingPrincipalsInput{ThingName: thingName}, func(page *iot.ListThingPrincipalsOutput, lastPage bool) bool {
		for _, principal := range page.Principals {
			certificateIds = append(certificateIds, strings.TrimPrefix(*principal, certificateArnPrefix))

			_, innerErr = h.iot.DetachThingPrincipal(&iot.DetachThingPrincipalInput{ThingName: thingName, Principal: principal})
			if innerErr != nil {
				return false
			}
		}
		return !lastPage
	})
	if err != nil {
		return errors.WithStack(err)
	}
	if innerErr != nil {
		return errors.WithStack(innerErr)
	}

	_, err = h.iot.DeleteThingWithContext(ctx, &iot.DeleteThingInput{ThingName: thingName})
	if err != nil {
		return errors.WithStack(err)
	}

	for _, certificateId := range certificateIds {
		_, err = h.iot.UpdateCertificateWithContext(ctx, &iot.UpdateCertificateInput{CertificateId: &certificateId, NewStatus: aws.String(iot.CertificateStatusInactive)})
		if err != nil {
			return errors.WithStack(err)
		}

		_, err = h.iot.DeleteCertificateWithContext(ctx, &iot.DeleteCertificateInput{CertificateId: &certificateId, ForceDelete: aws.Bool(true)})
		if err != nil {
			return errors.WithStack(err)
		}
	}

	versions, err := h.iot.ListPolicyVersions(&iot.ListPolicyVersionsInput{PolicyName: thingName})
	if err != nil {
		return errors.WithStack(err)
	}

	for _, version := range versions.PolicyVersions {
		if *version.IsDefaultVersion {
			continue
		}

		_, err = h.iot.DeletePolicyVersion(&iot.DeletePolicyVersionInput{PolicyName: thingName, PolicyVersionId: version.VersionId})
		if err != nil {
			return errors.WithStack(err)
		}
	}

	_, err = h.iot.DeletePolicy(&iot.DeletePolicyInput{PolicyName: thingName})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
