package portaltunnel

import _ "embed"

//go:embed config.toml
var ConfigTOML []byte

//go:embed registry.json
var RegistryJSON []byte
