// Package portal provides Portal's embedded build manifests.
package portal

import _ "embed"

//go:embed config.toml
var ConfigTOML []byte

//go:embed registry.json
var RegistryJSON []byte

//go:embed llms.txt
var LLMsTXT []byte
