package project

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

//go:embed templates/manifest-readme.md
var manifestReadmeTemplate string

// TemplateData contains data for rendering templates.
type TemplateData struct {
	ProjectName string
	Friends     []Friend
	Threshold   int
}

// WriteManifestReadme creates the README.md file in the manifest directory.
func WriteManifestReadme(manifestDir string, data TemplateData) error {
	tmpl, err := template.New("readme").Parse(manifestReadmeTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	path := filepath.Join(manifestDir, "README.md")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating README.md: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	return nil
}

// FriendNames returns a comma-separated list of friend names.
func FriendNames(friends []Friend) string {
	names := make([]string, len(friends))
	for i, f := range friends {
		names[i] = f.Name
	}
	return strings.Join(names, ", ")
}
