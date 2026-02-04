package html

import (
	"strings"
)

// GenerateDocsHTML creates the documentation page HTML with embedded CSS.
// version is the rememory version string.
// githubURL is the URL to download CLI binaries.
func GenerateDocsHTML(version, githubURL string) string {
	html := docsHTMLTemplate

	// Embed styles
	html = strings.Replace(html, "{{STYLES}}", stylesCSS, 1)

	// Replace version and GitHub URL
	html = strings.Replace(html, "{{VERSION}}", version, -1)
	html = strings.Replace(html, "{{GITHUB_URL}}", githubURL, -1)

	return html
}
