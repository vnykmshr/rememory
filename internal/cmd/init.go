package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/eljojo/rememory/internal/project"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init [name]",
	Short: "Create a new rememory project",
	Long: `Create a new rememory project with a manifest directory and configuration.

The project will contain:
  - project.yml: Configuration with friends' contact information
  - manifest/: Directory for your secret files

Example:
  rememory init my-recovery-2026
  rememory init my-recovery --from ../old-project`,
	Args: cobra.MaximumNArgs(1),
	RunE: runInit,
}

var (
	initFrom string
)

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().StringVar(&initFrom, "from", "", "Base new project on existing project (copies friends)")
}

func runInit(cmd *cobra.Command, args []string) error {
	// Determine project name and path
	name := "recovery"
	if len(args) > 0 {
		name = args[0]
	}

	dir, err := filepath.Abs(name)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}

	// Check if directory already exists
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("directory already exists: %s", dir)
	}

	fmt.Printf("Creating new rememory project: %s/\n\n", name)

	var friends []project.Friend
	var threshold int

	// If --from is specified, copy friends from existing project
	if initFrom != "" {
		fromDir, err := filepath.Abs(initFrom)
		if err != nil {
			return fmt.Errorf("resolving --from path: %w", err)
		}

		existing, err := project.Load(fromDir)
		if err != nil {
			return fmt.Errorf("loading existing project: %w", err)
		}

		friends = existing.Friends
		threshold = existing.Threshold
		fmt.Printf("Copying configuration from: %s\n", initFrom)
		fmt.Printf("  Friends: %s\n", friendNames(friends))
		fmt.Printf("  Threshold: %d of %d\n\n", threshold, len(friends))
	} else {
		// Interactive prompts
		reader := bufio.NewReader(os.Stdin)

		// Number of friends
		fmt.Print("How many friends will hold shares? [5]: ")
		numStr, _ := reader.ReadString('\n')
		numStr = strings.TrimSpace(numStr)
		numFriends := 5
		if numStr != "" {
			n, err := strconv.Atoi(numStr)
			if err != nil || n < 2 {
				return fmt.Errorf("invalid number of friends (minimum 2)")
			}
			numFriends = n
		}

		// Threshold
		defaultThreshold := (numFriends + 1) / 2 // Majority by default
		if defaultThreshold < 2 {
			defaultThreshold = 2
		}
		fmt.Printf("How many shares needed to recover? [%d]: ", defaultThreshold)
		threshStr, _ := reader.ReadString('\n')
		threshStr = strings.TrimSpace(threshStr)
		threshold = defaultThreshold
		if threshStr != "" {
			t, err := strconv.Atoi(threshStr)
			if err != nil || t < 2 || t > numFriends {
				return fmt.Errorf("invalid threshold (must be 2-%d)", numFriends)
			}
			threshold = t
		}

		fmt.Println()

		// Collect friend information
		friends = make([]project.Friend, numFriends)
		for i := 0; i < numFriends; i++ {
			fmt.Printf("Friend %d:\n", i+1)

			fmt.Print("  Name: ")
			nameStr, _ := reader.ReadString('\n')
			nameStr = strings.TrimSpace(nameStr)
			if nameStr == "" {
				return fmt.Errorf("name is required")
			}
			friends[i].Name = nameStr

			fmt.Print("  Email: ")
			emailStr, _ := reader.ReadString('\n')
			emailStr = strings.TrimSpace(emailStr)
			if emailStr == "" {
				return fmt.Errorf("email is required")
			}
			friends[i].Email = emailStr

			fmt.Print("  Phone (optional): ")
			phoneStr, _ := reader.ReadString('\n')
			friends[i].Phone = strings.TrimSpace(phoneStr)

			fmt.Println()
		}
	}

	// Create the project
	p, err := project.New(dir, name, threshold, friends)
	if err != nil {
		return fmt.Errorf("creating project: %w", err)
	}

	// Write the manifest README template
	templateData := project.TemplateData{
		ProjectName: name,
		Friends:     friends,
		Threshold:   threshold,
	}
	if err := project.WriteManifestReadme(p.ManifestPath(), templateData); err != nil {
		return fmt.Errorf("creating manifest README: %w", err)
	}

	fmt.Printf("Created %s/\n", name)
	fmt.Printf("  - project.yml (edit to update friends)\n")
	fmt.Printf("  - manifest/README.md (add your secrets here)\n")
	fmt.Println()
	fmt.Println("Next: Add files to manifest/, then run `rememory seal`")

	return nil
}

func friendNames(friends []project.Friend) string {
	names := make([]string, len(friends))
	for i, f := range friends {
		names[i] = f.Name
	}
	return strings.Join(names, ", ")
}
