package identity

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

const (
	DefaultSuiEd25519PaymentDerivationPath = "m/44'/784'/0'/0'/0'"

	bip32HardenedOffset = uint32(0x80000000)
)

type derivationPath []uint32

func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

func deriveEd25519PrivateKeyFromMnemonic(rawMnemonic, rawDerivationPath string) (string, string, error) {
	mnemonic := normalizeMnemonic(rawMnemonic)
	if mnemonic == "" {
		return "", "", errors.New("identity mnemonic is required")
	}

	derivationPath := strings.TrimSpace(rawDerivationPath)
	if derivationPath == "" {
		derivationPath = DefaultSuiEd25519PaymentDerivationPath
	}
	if !strings.HasPrefix(derivationPath, "m/") {
		return "", "", errors.New("sui ed25519 derivation path must be absolute")
	}
	path, err := parseDerivationPath(derivationPath)
	if err != nil {
		return "", "", fmt.Errorf("parse sui ed25519 derivation path: %w", err)
	}
	for _, child := range path {
		if child < bip32HardenedOffset {
			return "", "", errors.New("sui ed25519 derivation path components must be hardened")
		}
	}

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return "", "", fmt.Errorf("validate identity mnemonic: %w", err)
	}
	privateKey, err := deriveSLIP10Ed25519PrivateKey(seed, path)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(privateKey), path.String(), nil
}

func normalizeMnemonic(raw string) string {
	return strings.ToLower(strings.Join(strings.Fields(raw), " "))
}

func parseDerivationPath(raw string) (derivationPath, error) {
	components := strings.Split(raw, "/")
	if len(components) == 0 {
		return nil, errors.New("empty derivation path")
	}

	var path derivationPath
	switch strings.TrimSpace(components[0]) {
	case "":
		return nil, errors.New("ambiguous path: use 'm/' prefix for absolute paths, or no leading '/' for relative ones")
	case "m":
		components = components[1:]
	default:
		return nil, errors.New("derivation path must start with 'm/'")
	}
	if len(components) == 0 {
		return nil, errors.New("empty derivation path")
	}

	for _, component := range components {
		component = strings.TrimSpace(component)
		hardened := strings.HasSuffix(component, "'")
		if hardened {
			component = strings.TrimSpace(strings.TrimSuffix(component, "'"))
		}
		value, err := strconv.ParseUint(component, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid component: %s", component)
		}
		if hardened {
			if value >= uint64(bip32HardenedOffset) {
				return nil, fmt.Errorf("component %d out of allowed hardened range [0, %d]", value, bip32HardenedOffset-1)
			}
			value += uint64(bip32HardenedOffset)
		}
		path = append(path, uint32(value))
	}
	return path, nil
}

func (path derivationPath) String() string {
	var builder strings.Builder
	builder.WriteByte('m')
	for _, component := range path {
		builder.WriteByte('/')
		hardened := component >= bip32HardenedOffset
		if hardened {
			component -= bip32HardenedOffset
		}
		builder.WriteString(strconv.FormatUint(uint64(component), 10))
		if hardened {
			builder.WriteByte('\'')
		}
	}
	return builder.String()
}

func deriveSLIP10Ed25519PrivateKey(seed []byte, path derivationPath) ([]byte, error) {
	if len(seed) == 0 {
		return nil, errors.New("identity mnemonic seed is required")
	}
	if len(path) == 0 {
		return nil, errors.New("identity derivation path is required")
	}

	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	_, _ = mac.Write(seed)
	digest := mac.Sum(nil)
	privateKey := append([]byte(nil), digest[:32]...)
	chainCode := append([]byte(nil), digest[32:]...)

	for _, child := range path {
		if child < bip32HardenedOffset {
			return nil, errors.New("ed25519 child derivation requires hardened path")
		}
		privateKey, chainCode = deriveSLIP10Ed25519ChildPrivateKey(privateKey, chainCode, child)
	}
	return privateKey, nil
}

func deriveSLIP10Ed25519ChildPrivateKey(parentPrivateKey, parentChainCode []byte, child uint32) ([]byte, []byte) {
	data := make([]byte, 0, 37)
	data = append(data, 0)
	data = append(data, parentPrivateKey...)
	var childBytes [4]byte
	binary.BigEndian.PutUint32(childBytes[:], child)
	data = append(data, childBytes[:]...)

	mac := hmac.New(sha512.New, parentChainCode)
	_, _ = mac.Write(data)
	digest := mac.Sum(nil)
	return append([]byte(nil), digest[:32]...), append([]byte(nil), digest[32:]...)
}
