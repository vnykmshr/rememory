//go:build !js

package html

import (
	_ "embed"
)

// Embed create.wasm only in non-WASM builds (i.e., the CLI binary)
// This avoids circular dependency since create.wasm itself embeds the html package.

//go:embed assets/create.wasm
var createWASMEmbed []byte

func init() {
	createWASM = createWASMEmbed
}
