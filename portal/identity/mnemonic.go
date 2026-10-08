package identity

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip39"
)

const (
	DefaultEVMIdentityDerivationPath = "m/44'/60'/0'/0/0"

	bip32HardenedOffset = uint32(0x80000000)
)

type derivationPath []uint32

var defaultEVMRootDerivationPath = derivationPath{
	bip32HardenedOffset + 44,
	bip32HardenedOffset + 60,
	bip32HardenedOffset,
	0,
}

func deriveSecp256k1PrivateKeyFromMnemonic(rawMnemonic, rawDerivationPath string) (string, string, error) {
	mnemonic := normalizeMnemonic(rawMnemonic)
	if mnemonic == "" {
		return "", "", errors.New("identity mnemonic is required")
	}

	derivationPath := strings.TrimSpace(rawDerivationPath)
	derivationPath = cmp.Or(derivationPath, DefaultEVMIdentityDerivationPath)
	path, err := parseDerivationPath(derivationPath)
	if err != nil {
		return "", "", fmt.Errorf("parse identity derivation path: %w", err)
	}

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return "", "", fmt.Errorf("validate identity mnemonic: %w", err)
	}
	privateKey, err := deriveBIP32Secp256k1PrivateKey(seed, path)
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
		path = append(path, defaultEVMRootDerivationPath...)
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

func deriveBIP32Secp256k1PrivateKey(seed []byte, path derivationPath) ([]byte, error) {
	if len(seed) == 0 {
		return nil, errors.New("identity mnemonic seed is required")
	}
	if len(path) == 0 {
		return nil, errors.New("identity derivation path is required")
	}

	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, _ = mac.Write(seed)
	digest := mac.Sum(nil)

	privateKey, err := normalizeBIP32PrivateKey(digest[:32])
	if err != nil {
		return nil, fmt.Errorf("derive identity master key: %w", err)
	}
	chainCode := append([]byte(nil), digest[32:]...)

	for _, child := range path {
		privateKey, chainCode, err = deriveBIP32Secp256k1ChildPrivateKey(privateKey, chainCode, child)
		if err != nil {
			return nil, fmt.Errorf("derive identity child key %d: %w", child, err)
		}
	}
	return privateKey, nil
}

func deriveBIP32Secp256k1ChildPrivateKey(parentPrivateKey, parentChainCode []byte, child uint32) ([]byte, []byte, error) {
	if len(parentChainCode) != 32 {
		return nil, nil, errors.New("parent chain code must be 32 bytes")
	}
	parentKey, err := normalizeBIP32PrivateKey(parentPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parent private key: %w", err)
	}

	data := make([]byte, 0, 37)
	if child >= bip32HardenedOffset {
		data = append(data, 0)
		data = append(data, parentKey...)
	} else {
		data = append(data, secp256k1.PrivKeyFromBytes(parentKey).PubKey().SerializeCompressed()...)
	}
	var childBytes [4]byte
	binary.BigEndian.PutUint32(childBytes[:], child)
	data = append(data, childBytes[:]...)

	mac := hmac.New(sha512.New, parentChainCode)
	_, _ = mac.Write(data)
	digest := mac.Sum(nil)

	childKey, err := addBIP32PrivateKeys(digest[:32], parentKey)
	if err != nil {
		return nil, nil, err
	}
	return childKey, append([]byte(nil), digest[32:]...), nil
}

func addBIP32PrivateKeys(left, right []byte) ([]byte, error) {
	order := secp256k1.Params().N
	leftInt := new(big.Int).SetBytes(left)
	if leftInt.Sign() == 0 || leftInt.Cmp(order) >= 0 {
		return nil, errors.New("child key offset is outside the secp256k1 order")
	}
	rightInt := new(big.Int).SetBytes(right)
	if rightInt.Sign() == 0 || rightInt.Cmp(order) >= 0 {
		return nil, errors.New("parent private key is outside the secp256k1 order")
	}

	child := leftInt.Add(leftInt, rightInt)
	child.Mod(child, order)
	if child.Sign() == 0 {
		return nil, errors.New("derived private key is zero")
	}
	return padded32(child), nil
}

func normalizeBIP32PrivateKey(raw []byte) ([]byte, error) {
	key := new(big.Int).SetBytes(raw)
	if key.Sign() == 0 {
		return nil, errors.New("private key is zero")
	}
	if key.Cmp(secp256k1.Params().N) >= 0 {
		return nil, errors.New("private key is outside the secp256k1 order")
	}
	return padded32(key), nil
}

func padded32(value *big.Int) []byte {
	out := make([]byte, 32)
	value.FillBytes(out)
	return out
}
