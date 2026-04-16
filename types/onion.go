package types

type OnionLayer struct {
	EphemeralPublicKey string `json:"e"` // SDK's ephemeral WireGuard public key for this layer
	NextHopOverlayIP   string `json:"n"` // Next hop's WireGuard overlay IP
	Payload            []byte `json:"p"` // Encrypted payload for the next hop
}

type FinalLayer struct {
	AccessToken string `json:"a"`
}
