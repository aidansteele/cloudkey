package main

import (
	"context"
	"fmt"
	"github.com/aidansteele/cloudkey/cmds"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "cloudkey",
		Short: "cloudkey is a solution for secret-less AWS access",
	}

	root.PersistentFlags().String("card", "", "Name of Yubikey. Optional if only one key is connected")

	credentialsCmd := &cobra.Command{
		Use:   "credentials",
		Short: "To be invoked by ~/.aws/config credential_process",
		RunE:  cmds.CredentialsCmd,
	}

	enrolCmd := &cobra.Command{
		Use:   "enrol",
		Short: "Enrol a new identity and smart card",
		RunE:  cmds.EnrolCmd,
	}

	enrolCmd.PersistentFlags().String("identity", "", "Name of identity to enrol")
	enrolCmd.PersistentFlags().StringSlice("role", []string{}, "IAM role name(s) to attach to identity")

	root.AddCommand(
		credentialsCmd,
		enrolCmd,
	)

	ctx := context.Background()
	err := root.ExecuteContext(ctx)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}
}
