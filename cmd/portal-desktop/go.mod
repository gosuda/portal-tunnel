module github.com/gosuda/portal-tunnel/v2/cmd/portal-desktop

go 1.27.3

// The desktop client builds against the Agent of the same checkout, and its
// GUI dependencies stay out of the module the CLI, SDK and relay build from.
replace github.com/gosuda/portal-tunnel/v2 => ../..

require (
	github.com/gosuda/portal-tunnel/v2 v2.0.0-00010101000000-000000000000
	github.com/ironpark/ggui v0.6.2
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/beevik/etree v1.8.1 // indirect
	github.com/btcsuite/btcutil v1.0.2 // indirect
	github.com/coder/websocket v1.8.15 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/ebitengine/hideconsole v1.0.0 // indirect
	github.com/ebitengine/purego v0.11.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.9 // indirect
	github.com/gogpu/naga v0.21.10 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/gosuda/keyless_tls v0.0.6 // indirect
	github.com/gosuda/x402-facilitator v0.0.6-0.20261114131219-7c523e6478da // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/iotaledger/bcs-go v0.0.0-20250716100925-71f848cac593 // indirect
	github.com/iotaledger/hive.go/constraints v0.0.0-20240520064018-c635e5900894 // indirect
	github.com/ironpark/ggfx v0.0.0-20261122101835-96cb5098aa06 // indirect
	github.com/ironpark/ggwd v0.0.0-20261120121552-0b5175d66b9d // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	github.com/pelletier/go-toml/v2 v2.4.3 // indirect
	github.com/quic-go/quic-go v0.65.0 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/russellhaering/gosaml2 v0.12.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.1 // indirect
	github.com/samber/lo v1.49.1 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/image v0.46.0 // indirect
	golang.org/x/net v0.63.0 // indirect
	golang.org/x/oauth2 v0.38.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261104224025-d1e00e9f33ab // indirect
	google.golang.org/grpc v1.85.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
