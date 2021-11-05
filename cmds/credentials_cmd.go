package cmds

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/aidansteele/cloudkey/iotcreds"
	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"os"
	"time"
)

func CredentialsCmd(cmd *cobra.Command, args []string) error {
	roleName := os.Getenv("CLOUDKEY_ROLENAME")
	if roleName == "" {
		if len(args) == 1 {
			roleName = args[0]
		} else {
			fmt.Fprintln(os.Stderr, "Must specify IAM role name as argument")
			os.Exit(1)
		}
	}

	card, _ := cmd.PersistentFlags().GetString("card")
	yk, err := openCard(&card)
	if err != nil {
		return err
	}
	defer yk.Close()

	cert, err := yk.Certificate(piv.SlotCardAuthentication)
	if err != nil {
	    return errors.WithStack(err)
	}

	priv, err := yk.PrivateKey(piv.SlotCardAuthentication, cert.PublicKey, piv.KeyAuth{})
	if err != nil {
		return errors.WithStack(err)
	}

	certificate := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  priv,
	}

	endpoint := fmt.Sprintf("https://%s", cert.Subject.Organization[0])
	identity := cert.Subject.CommonName

	creds, err := iotcreds.Retrieve(endpoint, roleName, identity, certificate)
	if err != nil {
		return err
	}

	j, _ := json.Marshal(credentialProcessOutput{
		Version:         1,
		AccessKeyId:     creds.AccessKeyId,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      creds.Expiration.Format(time.RFC3339),
	})
	fmt.Println(string(j))

	return nil
}

type credentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}
