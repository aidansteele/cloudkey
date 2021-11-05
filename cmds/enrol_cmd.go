package cmds

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/aidansteele/cloudkey/handler"
	"github.com/aidansteele/cloudkey/types"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"strings"
	"syscall"
)

func EnrolCmd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	card, _ := cmd.PersistentFlags().GetString("card")
	identityName, _ := cmd.PersistentFlags().GetString("identity")
	roles, _ := cmd.PersistentFlags().GetStringSlice("roles")

	sess, err := session.NewSessionWithOptions(session.Options{SharedConfigState: session.SharedConfigEnable})
	if err != nil {
		return errors.WithStack(err)
	}

	h := handler.New(sess)

	yk, err := openCard(&card)
	if err != nil {
		return err
	}
	defer yk.Close()

	fmt.Printf("Enter your PIN for '%s': \n", card)
	pin, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return errors.WithStack(err)
	}

	meta, err := yk.Metadata(string(pin))
	if err != nil {
		return errors.WithStack(err)
	}

	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyNever,
	}

	slot := piv.SlotCardAuthentication
	pub, err := yk.GenerateKey(*meta.ManagementKey, slot, key)
	if err != nil {
		return errors.WithStack(err)
	}
	fmt.Println("Generated new private key in card authentication slot")

	priv, err := yk.PrivateKey(slot, pub, piv.KeyAuth{PIN: string(pin)})
	if err != nil {
		return errors.WithStack(err)
	}

	slotCert, err := yk.Attest(slot)
	if err != nil {
		return errors.WithStack(err)
	}

	attestCert, err := yk.AttestationCertificate()
	if err != nil {
		return errors.WithStack(err)
	}

	verification, err := piv.Verify(attestCert, slotCert)
	if err != nil {
		return errors.WithStack(err)
	}
	fmt.Println("Verified that private key is stored in Yubico device")

	serial := fmt.Sprintf("YK%d", verification.Serial)
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			SerialNumber: serial,
			CommonName:   identityName,
			Organization: []string{h.Endpoint()},
		},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return errors.WithStack(err)
	}

	putInput := types.PutIdentityInput{
		IdentityName:          identityName,
		AttestationDERs:       [][]byte{slotCert.Raw, attestCert.Raw},
		CertificateRequestDER: csr,
	}

	fmt.Println("Sending certificate signing request to AWS IoT")
	putIdentity, err := h.PutIdentity(ctx, &putInput)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(putIdentity.CertificateDER)
	if err != nil {
		return errors.WithStack(err)
	}
	fmt.Printf("Received certificate from AWS IoT with ID: %s\n", putIdentity.CertificateId)

	err = yk.SetCertificate(*meta.ManagementKey, slot, cert)
	if err != nil {
		return errors.WithStack(err)
	}
	fmt.Println("Stored certificate on device")

	if len(roles) > 0 {
		_, err = h.PutIdentityAttachedRoles(ctx, &types.PutIdentityAttachedRolesInput{
			IdentityName: identityName,
			RoleNames:    roles,
		})
		if err != nil {
			return err
		}

		fmt.Printf("Attached role names: %s\n", strings.Join(roles, ", "))
	}

	return nil
}

func openCard(cardptr *string) (*piv.YubiKey, error) {
	card := ""
	if cardptr != nil {
		card = *cardptr
	}

	if card == "" {
		cards, err := piv.Cards()
		if err != nil {
			return nil, errors.WithStack(err)
		}

		switch len(cards) {
		case 0:
			return nil, errors.New("must have a yubikey connected")
		case 1:
			card = cards[0]
			if cardptr != nil {
				*cardptr = card
			}
		default:
			return nil, errors.New("must specify a card if more than one is connected")
		}
	}

	yk, err := piv.Open(card)
	return yk, errors.WithStack(err)
}
