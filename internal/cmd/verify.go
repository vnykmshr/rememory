package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/eljojo/rememory/internal/crypto"
	"github.com/eljojo/rememory/internal/project"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the integrity of sealed files",
	Long: `Verify checks that the encrypted manifest and share files match
the checksums stored in project.yml.

Run this command inside a project directory to verify:
  - MANIFEST.age exists and matches its checksum
  - All share files exist and match their checksums

This helps detect if files have been corrupted or modified.`,
	RunE: runVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	// Find and load the project
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting current directory: %w", err)
	}

	projectDir, err := project.FindProjectDir(cwd)
	if err != nil {
		return err
	}

	p, err := project.Load(projectDir)
	if err != nil {
		return fmt.Errorf("loading project: %w", err)
	}

	if p.Sealed == nil {
		return fmt.Errorf("project has not been sealed yet; run 'rememory seal' first")
	}

	allOK := true

	// Verify manifest file
	manifestPath := p.ManifestAgePath()
	fmt.Printf("Checking %s... ", filepath.Base(manifestPath))

	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		fmt.Println("MISSING")
		allOK = false
	} else {
		checksum, err := crypto.HashFile(manifestPath)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			allOK = false
		} else if checksum != p.Sealed.ManifestChecksum {
			fmt.Println("CHECKSUM MISMATCH")
			fmt.Printf("  Expected: %s\n", p.Sealed.ManifestChecksum)
			fmt.Printf("  Got:      %s\n", checksum)
			allOK = false
		} else {
			fmt.Println("OK")
		}
	}

	// Verify share files
	for _, shareInfo := range p.Sealed.Shares {
		sharePath := filepath.Join(p.Path, shareInfo.File)
		fmt.Printf("Checking %s... ", filepath.Base(sharePath))

		if _, err := os.Stat(sharePath); os.IsNotExist(err) {
			fmt.Println("MISSING")
			allOK = false
			continue
		}

		checksum, err := crypto.HashFile(sharePath)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			allOK = false
			continue
		}

		if checksum != shareInfo.Checksum {
			fmt.Println("CHECKSUM MISMATCH")
			fmt.Printf("  Expected: %s\n", shareInfo.Checksum)
			fmt.Printf("  Got:      %s\n", checksum)
			allOK = false
		} else {
			fmt.Println("OK")
		}
	}

	fmt.Println()
	if allOK {
		fmt.Println("All files verified.")
		return nil
	}

	return fmt.Errorf("verification failed")
}
