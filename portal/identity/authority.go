package identity

import (
	"errors"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type Authority interface {
	Identity() types.Identity
	SignEd25519(payload []byte) (string, error)
	SignSuiPersonalMessage(message []byte) (string, error)
}

type LocalAuthority struct {
	identity types.Identity
}

func NewLocalAuthority(raw types.Identity) (LocalAuthority, error) {
	normalized, err := normalizeStoredIdentity(raw)
	if err != nil {
		return LocalAuthority{}, err
	}
	if normalized.SuiPrivateKey == "" {
		return LocalAuthority{}, errors.New("authority sui private key is required")
	}
	if normalized.SuiPublicKey == "" {
		return LocalAuthority{}, errors.New("authority sui public key is required")
	}
	if normalized.SuiAddress == "" {
		return LocalAuthority{}, errors.New("authority sui address is required")
	}
	return LocalAuthority{identity: normalized}, nil
}

func (a LocalAuthority) Identity() types.Identity {
	identity := a.identity.Copy()
	identity.PrivateKey = ""
	identity.Mnemonic = ""
	identity.DerivationPath = ""
	identity.SuiPrivateKey = ""
	identity.SuiDerivationPath = ""
	identity.TokenSecret = ""
	return identity
}

func (a LocalAuthority) SignEd25519(payload []byte) (string, error) {
	return SignEd25519Hex(payload, a.identity.SuiPrivateKey)
}

func (a LocalAuthority) SignSuiPersonalMessage(message []byte) (string, error) {
	return SignSuiPersonalMessage(message, a.identity.SuiPrivateKey)
}
