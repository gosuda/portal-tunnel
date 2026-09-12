package identity

import (
	"github.com/gosuda/portal-tunnel/v2/types"
)

type Authority interface {
	Identity() types.Identity
	SignEthereumPersonalMessage(message string) (string, error)
	SignSHA256Secp256k1(payload []byte) (Secp256k1Signature, error)
}

type LocalAuthority struct {
	identity types.Identity
}

func NewLocalAuthority(raw types.Identity) (LocalAuthority, error) {
	normalized, err := resolveKeyMaterial(raw)
	if err != nil {
		return LocalAuthority{}, err
	}
	return LocalAuthority{identity: normalized}, nil
}

func (a LocalAuthority) Identity() types.Identity {
	identity := a.identity.Copy()
	identity.PrivateKey = ""
	identity.Mnemonic = ""
	identity.DerivationPath = ""
	identity.TokenSecret = ""
	return identity
}

func (a LocalAuthority) SignEthereumPersonalMessage(message string) (string, error) {
	return signEthereumPersonalMessage(message, a.identity.PrivateKey)
}

func (a LocalAuthority) SignSHA256Secp256k1(payload []byte) (Secp256k1Signature, error) {
	privateKey, _, err := parseSecp256k1PrivateKeyHex(a.identity.PrivateKey, true)
	if err != nil {
		return Secp256k1Signature{}, err
	}
	return signSHA256Secp256k1(payload, privateKey)
}
