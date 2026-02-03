package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "rememory",
	Short: "Encrypt secrets and split access among trusted friends",
	Long: `ReMemory encrypts a manifest of secrets with age, splits the passphrase
using Shamir's Secret Sharing, and creates recovery bundles for trusted friends.

Create a project:    rememory init my-recovery
Seal the manifest:   rememory seal
Recover from shares: rememory recover share1.txt share2.txt share3.txt`,
}

func Execute(version string) error {
	rootCmd.Version = version
	return rootCmd.Execute()
}
