package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"
	"golang.org/x/crypto/blake2b"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	suiIntentScopePersonalMessage byte = 3
	suiIntentVersionV0            byte = 0
	suiIntentAppIDSui             byte = 0
)

type SuiZkLoginVerifier func(author string, message []byte, signature string) (bool, error)

func NormalizeSuiAddress(raw string) (string, error) {
	address := suischeme.NormalizeAddress(raw)
	if address == "" {
		return "", errors.New("address must be a valid Sui address")
	}
	return address, nil
}

func ResolveSuiEd25519Identity(rawPrivateKey string) (types.Identity, error) {
	privateKeyText := strings.TrimSpace(rawPrivateKey)
	if privateKeyText == "" {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return types.Identity{}, fmt.Errorf("generate sui ed25519 private key: %w", err)
		}
		privateKeyText = hex.EncodeToString(privateKey.Seed())
	}
	privateKey, normalizedKeyHex, err := parseEd25519PrivateKeyHex(privateKeyText)
	if err != nil {
		return types.Identity{}, err
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return types.Identity{}, errors.New("invalid sui ed25519 public key")
	}
	address := suischeme.AddressFromPublicKey(suischeme.SignatureSchemeEd25519, publicKey)
	if address == "" {
		return types.Identity{}, errors.New("derive sui address")
	}
	return types.Identity{
		Address:       address,
		PublicKey:     hex.EncodeToString(publicKey),
		PrivateKey:    normalizedKeyHex,
		SuiAddress:    address,
		SuiPublicKey:  hex.EncodeToString(publicKey),
		SuiPrivateKey: normalizedKeyHex,
	}, nil
}

func ResolveSuiEd25519IdentityFromMnemonic(rawMnemonic, rawDerivationPath string) (types.Identity, error) {
	privateKey, derivationPath, err := deriveEd25519PrivateKeyFromMnemonic(rawMnemonic, rawDerivationPath)
	if err != nil {
		return types.Identity{}, err
	}
	resolved, err := ResolveSuiEd25519Identity(privateKey)
	if err != nil {
		return types.Identity{}, err
	}
	resolved.SuiDerivationPath = derivationPath
	return resolved, nil
}

func normalizeStoredSuiIdentity(normalized *types.Identity) error {
	normalized.SuiAddress = strings.TrimSpace(normalized.SuiAddress)
	normalized.SuiPublicKey = strings.TrimSpace(normalized.SuiPublicKey)
	normalized.SuiPrivateKey = strings.TrimSpace(normalized.SuiPrivateKey)
	normalized.SuiDerivationPath = strings.TrimSpace(normalized.SuiDerivationPath)

	if normalized.Mnemonic != "" {
		resolved, err := ResolveSuiEd25519IdentityFromMnemonic(normalized.Mnemonic, normalized.SuiDerivationPath)
		if err != nil {
			return err
		}
		normalized.SuiDerivationPath = resolved.SuiDerivationPath
		if normalized.SuiPrivateKey == "" {
			normalized.SuiPrivateKey = resolved.SuiPrivateKey
		} else if !strings.EqualFold(utils.TrimHexPrefix(normalized.SuiPrivateKey), resolved.SuiPrivateKey) {
			return errors.New("identity sui private key does not match mnemonic")
		}
	} else if normalized.SuiDerivationPath != "" {
		return errors.New("identity sui_derivation_path requires mnemonic")
	}

	switch {
	case normalized.SuiPrivateKey != "":
		resolved, err := ResolveSuiEd25519Identity(normalized.SuiPrivateKey)
		if err != nil {
			return fmt.Errorf("resolve sui ed25519 identity: %w", err)
		}
		if normalized.SuiPublicKey != "" && !strings.EqualFold(utils.TrimHexPrefix(normalized.SuiPublicKey), resolved.SuiPublicKey) {
			return errors.New("identity sui public key does not match private key")
		}
		if normalized.SuiAddress != "" && suischeme.NormalizeAddress(normalized.SuiAddress) != resolved.SuiAddress {
			return errors.New("identity sui address does not match private key")
		}
		normalized.SuiAddress = resolved.SuiAddress
		normalized.SuiPublicKey = resolved.SuiPublicKey
		normalized.SuiPrivateKey = resolved.SuiPrivateKey
	case normalized.SuiPublicKey != "":
		publicKey, err := parseEd25519PublicKeyHex(normalized.SuiPublicKey)
		if err != nil {
			return err
		}
		address := suischeme.AddressFromPublicKey(suischeme.SignatureSchemeEd25519, publicKey)
		if normalized.SuiAddress != "" && suischeme.NormalizeAddress(normalized.SuiAddress) != address {
			return errors.New("identity sui address does not match public key")
		}
		normalized.SuiAddress = address
		normalized.SuiPublicKey = hex.EncodeToString(publicKey)
	case normalized.SuiAddress != "":
		address, err := NormalizeSuiAddress(normalized.SuiAddress)
		if err != nil {
			return err
		}
		normalized.SuiAddress = address
	}
	if normalized.SuiAddress != "" {
		normalized.Address = normalized.SuiAddress
	}
	if normalized.SuiPublicKey != "" {
		normalized.PublicKey = normalized.SuiPublicKey
	}
	if normalized.SuiPrivateKey != "" {
		normalized.PrivateKey = normalized.SuiPrivateKey
	}
	return nil
}

func SignSuiPersonalMessage(message []byte, rawPrivateKey string) (string, error) {
	privateKey, _, err := parseEd25519PrivateKeyHex(rawPrivateKey)
	if err != nil {
		return "", err
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("invalid sui ed25519 public key")
	}
	digest := suiPersonalMessageDigest(message)
	signature := ed25519.Sign(privateKey, digest)
	serialized := make([]byte, 0, 1+len(signature)+len(publicKey))
	serialized = append(serialized, suischeme.SignatureSchemeEd25519)
	serialized = append(serialized, signature...)
	serialized = append(serialized, publicKey...)
	return base64.StdEncoding.EncodeToString(serialized), nil
}

func VerifySuiPersonalMessageSignature(message []byte, signature string, verifier SuiZkLoginVerifier) (string, error) {
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return "", errors.New("signature is required")
	}
	if len(message) == 0 {
		return "", errors.New("message is required")
	}
	serialized, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return "", fmt.Errorf("invalid sui signature: %w", err)
	}
	if len(serialized) == 0 {
		return "", errors.New("invalid sui signature")
	}

	switch serialized[0] {
	case suischeme.SignatureSchemeEd25519:
		if len(serialized) != 1+ed25519.SignatureSize+ed25519.PublicKeySize {
			return "", errors.New("invalid sui ed25519 signature length")
		}
		signatureBytes := serialized[1 : 1+ed25519.SignatureSize]
		publicKey := serialized[1+ed25519.SignatureSize:]
		if !ed25519.Verify(ed25519.PublicKey(publicKey), suiPersonalMessageDigest(message), signatureBytes) {
			return "", errors.New("sui signature is invalid")
		}
		address := suischeme.AddressFromPublicKey(suischeme.SignatureSchemeEd25519, publicKey)
		if address == "" {
			return "", errors.New("derive sui address")
		}
		return address, nil
	case suischeme.SignatureSchemeZkLogin:
		author, err := suischeme.AddressFromZkLoginSignature(signature)
		if err != nil {
			return "", err
		}
		if verifier == nil {
			return "", errors.New("zkLogin signature verification is unavailable")
		}
		ok, err := verifier(author, message, signature)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("zkLogin signature is invalid")
		}
		return author, nil
	default:
		return "", errors.New("unsupported sui signature scheme")
	}
}

func SignEd25519Hex(payload []byte, rawPrivateKey string) (string, error) {
	privateKey, _, err := parseEd25519PrivateKeyHex(rawPrivateKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(privateKey, payload)), nil
}

func VerifyEd25519Hex(payload []byte, publicKeyHex, signatureHex string) error {
	publicKey, err := parseEd25519PublicKeyHex(publicKeyHex)
	if err != nil {
		return err
	}
	signatureText := strings.TrimSpace(signatureHex)
	if signatureText == "" {
		return errors.New("signature is required")
	}
	signatureText = utils.TrimHexPrefix(signatureText)
	signature, err := hex.DecodeString(signatureText)
	if err != nil {
		return errors.New("signature must be hex encoded")
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature must be %d bytes", ed25519.SignatureSize)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("signature is invalid")
	}
	return nil
}

func SuiAddressFromEd25519PublicKeyHex(rawPublicKey string) (string, error) {
	publicKey, err := parseEd25519PublicKeyHex(rawPublicKey)
	if err != nil {
		return "", err
	}
	address := suischeme.AddressFromPublicKey(suischeme.SignatureSchemeEd25519, publicKey)
	if address == "" {
		return "", errors.New("derive sui address")
	}
	return address, nil
}

func suiPersonalMessageDigest(message []byte) []byte {
	bcsMessage := make([]byte, 0, 5+len(message))
	n := uint64(len(message))
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			bcsMessage = append(bcsMessage, b)
			break
		}
		bcsMessage = append(bcsMessage, b|0x80)
	}
	bcsMessage = append(bcsMessage, message...)

	intentMessage := make([]byte, 0, 3+len(bcsMessage))
	intentMessage = append(intentMessage, suiIntentScopePersonalMessage, suiIntentVersionV0, suiIntentAppIDSui)
	intentMessage = append(intentMessage, bcsMessage...)
	digest := blake2b.Sum256(intentMessage)
	return digest[:]
}

func parseEd25519PrivateKeyHex(raw string) (ed25519.PrivateKey, string, error) {
	privateKeyHex := strings.TrimSpace(raw)
	if privateKeyHex == "" {
		return nil, "", errors.New("sui ed25519 private key is required")
	}
	privateKeyHex = trimHexPrefix(privateKeyHex)
	decoded, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, "", errors.New("sui ed25519 private key must be hex encoded")
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), hex.EncodeToString(decoded), nil
	case ed25519.PrivateKeySize:
		privateKey := ed25519.PrivateKey(append([]byte(nil), decoded...))
		return privateKey, hex.EncodeToString(privateKey.Seed()), nil
	default:
		return nil, "", fmt.Errorf("sui ed25519 private key must be %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func parseEd25519PublicKeyHex(raw string) (ed25519.PublicKey, error) {
	publicKeyHex := strings.TrimSpace(raw)
	if publicKeyHex == "" {
		return nil, errors.New("sui ed25519 public key is required")
	}
	publicKeyHex = trimHexPrefix(publicKeyHex)
	decoded, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, errors.New("sui ed25519 public key must be hex encoded")
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("sui ed25519 public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(append([]byte(nil), decoded...)), nil
}
