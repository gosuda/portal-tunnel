package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	// compactSecp256k1SignatureSize is the byte length of a compact
	// recoverable secp256k1 ECDSA signature.
	compactSecp256k1SignatureSize = 65
	// rawSecp256k1SignatureSize is the byte length of the JOSE ES256K
	// signature form, r || s with no recovery header.
	rawSecp256k1SignatureSize = 64
)

// ErrSecp256k1SignatureInvalid marks a well-formed signature that does not
// verify for the payload and public key.
var ErrSecp256k1SignatureInvalid = errors.New("signature is invalid")

type Secp256k1Signature struct {
	compact []byte
}

func newSecp256k1SignatureFromCompact(compact []byte) (Secp256k1Signature, error) {
	normalized, err := copySecp256k1CompactSignature(compact)
	if err != nil {
		return Secp256k1Signature{}, err
	}
	return Secp256k1Signature{compact: normalized}, nil
}

func (s Secp256k1Signature) Compact() ([]byte, error) {
	return copySecp256k1CompactSignature(s.compact)
}

func (s Secp256k1Signature) Raw64() ([]byte, error) {
	compact, err := copySecp256k1CompactSignature(s.compact)
	if err != nil {
		return nil, err
	}

	signature := make([]byte, rawSecp256k1SignatureSize)
	copy(signature[:32], compact[1:33])
	copy(signature[32:], compact[33:65])
	return signature, nil
}

func (s Secp256k1Signature) DERHex() (string, error) {
	raw, err := s.Raw64()
	if err != nil {
		return "", err
	}

	signature, err := secp256k1SignatureFromRaw64(raw)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature.Serialize()), nil
}

func NormalizeEVMAddress(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("address is required")
	}
	hexPart := trimHexPrefix(trimmed)
	if hexPart == trimmed {
		return "", errors.New("address must start with 0x")
	}
	if len(hexPart) != 40 {
		return "", errors.New("address must be 20 bytes")
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return "", errors.New("address must be hex encoded")
	}

	lowerHex := strings.ToLower(hexPart)
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write([]byte(lowerHex))
	hash := hasher.Sum(nil)

	var builder strings.Builder
	builder.Grow(len(lowerHex))
	for idx, ch := range lowerHex {
		if ch >= '0' && ch <= '9' {
			builder.WriteRune(ch)
			continue
		}

		nibble := hash[idx/2]
		if idx%2 == 0 {
			nibble >>= 4
		} else {
			nibble &= 0x0f
		}
		if nibble > 7 {
			builder.WriteRune(ch - ('a' - 'A'))
			continue
		}
		builder.WriteRune(ch)
	}

	checksummed := builder.String()
	if hexPart != lowerHex && hexPart != strings.ToUpper(hexPart) && hexPart != checksummed {
		return "", errors.New("address checksum is invalid")
	}
	return "0x" + checksummed, nil
}

func AddressFromCompressedPublicKeyHex(rawPublicKey string) (string, error) {
	publicKey, err := ParseSecp256k1PublicKeyHex(rawPublicKey)
	if err != nil {
		return "", err
	}

	uncompressed := publicKey.SerializeUncompressed()
	if len(uncompressed) != 65 || uncompressed[0] != 0x04 {
		return "", errors.New("invalid uncompressed secp256k1 public key")
	}

	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write(uncompressed[1:])
	hash := hasher.Sum(nil)

	return NormalizeEVMAddress("0x" + hex.EncodeToString(hash[len(hash)-20:]))
}

func signEthereumPersonalMessage(message, privateKeyHex string) (string, error) {
	privateKey, _, err := parseSecp256k1PrivateKeyHex(privateKeyHex, false)
	if err != nil {
		return "", err
	}

	data := []byte(message)
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(data)))
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write(prefix)
	_, _ = hasher.Write(data)
	hash := hasher.Sum(nil)

	compactSignature := ecdsa.SignCompact(privateKey, hash, false)
	if len(compactSignature) != 65 {
		return "", errors.New("invalid compact signature length")
	}

	signature := make([]byte, 65)
	copy(signature[:32], compactSignature[1:33])
	copy(signature[32:64], compactSignature[33:65])
	signature[64] = compactSignature[0]
	return "0x" + hex.EncodeToString(signature), nil
}

func ResolveSecp256k1Identity(rawPrivateKey string) (types.Identity, error) {
	privateKeyHex := strings.TrimSpace(rawPrivateKey)
	if privateKeyHex == "" {
		privateKey, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return types.Identity{}, fmt.Errorf("generate secp256k1 private key: %w", err)
		}
		privateKeyHex = hex.EncodeToString(privateKey.Serialize())
	}

	privateKey, normalizedKeyHex, err := parseSecp256k1PrivateKeyHex(privateKeyHex, true)
	if err != nil {
		return types.Identity{}, err
	}

	publicKeyHex := hex.EncodeToString(privateKey.PubKey().SerializeCompressed())
	address, err := AddressFromCompressedPublicKeyHex(publicKeyHex)
	if err != nil {
		return types.Identity{}, err
	}

	return types.Identity{
		Address:    address,
		PublicKey:  publicKeyHex,
		PrivateKey: normalizedKeyHex,
	}, nil
}

func signSHA256Secp256k1(payload []byte, privateKey *secp256k1.PrivateKey) (Secp256k1Signature, error) {
	if privateKey == nil {
		return Secp256k1Signature{}, errors.New("signing key is required")
	}
	hash := sha256.Sum256(payload)
	return newSecp256k1SignatureFromCompact(ecdsa.SignCompact(privateKey, hash[:], true))
}

// RecoverSHA256Secp256k1Compact recovers the public key from a compact
// recoverable signature over the SHA-256 digest of payload.
func RecoverSHA256Secp256k1Compact(payload, signature []byte) (*secp256k1.PublicKey, error) {
	if len(signature) != compactSecp256k1SignatureSize {
		return nil, errors.New("invalid compact signature length")
	}

	hash := sha256.Sum256(payload)
	publicKey, _, err := ecdsa.RecoverCompact(signature, hash[:])
	if err != nil {
		return nil, err
	}
	if publicKey == nil {
		return nil, ErrSecp256k1SignatureInvalid
	}
	return publicKey, nil
}

// VerifySHA256Secp256k1Raw64 verifies an ES256K raw r || s signature over the
// SHA-256 digest of payload.
func VerifySHA256Secp256k1Raw64(payload, signature []byte, publicKey *secp256k1.PublicKey) error {
	if publicKey == nil {
		return errors.New("verification key is required")
	}
	if len(signature) != rawSecp256k1SignatureSize {
		return errors.New("invalid es256k signature length")
	}

	parsed, err := secp256k1SignatureFromRaw64(signature)
	if err != nil {
		return err
	}

	return verifySHA256Secp256k1Signature(payload, parsed, publicKey)
}

func copySecp256k1CompactSignature(compact []byte) ([]byte, error) {
	if len(compact) != compactSecp256k1SignatureSize {
		return nil, errors.New("invalid compact signature length")
	}
	if _, err := secp256k1CompactRecoveryID(compact[0]); err != nil {
		return nil, err
	}
	if _, err := secp256k1SignatureFromRaw64(compact[1:]); err != nil {
		return nil, err
	}

	normalized := make([]byte, compactSecp256k1SignatureSize)
	copy(normalized, compact)
	return normalized, nil
}

func secp256k1CompactRecoveryID(header byte) (byte, error) {
	switch {
	case header >= 27 && header <= 30:
		return header - 27, nil
	case header >= 31 && header <= 34:
		return header - 31, nil
	default:
		return 0, errors.New("invalid compact signature header")
	}
}

func secp256k1SignatureFromRaw64(signature []byte) (*ecdsa.Signature, error) {
	if len(signature) != rawSecp256k1SignatureSize {
		return nil, errors.New("invalid es256k signature length")
	}

	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(signature[:32]); overflow || r.IsZero() {
		return nil, errors.New("invalid es256k signature r")
	}
	if overflow := s.SetByteSlice(signature[32:]); overflow || s.IsZero() {
		return nil, errors.New("invalid es256k signature s")
	}
	return ecdsa.NewSignature(&r, &s), nil
}

func VerifySHA256Secp256k1DER(payload []byte, publicKeyHex, signatureHex string) error {
	pubKey, err := ParseSecp256k1PublicKeyHex(publicKeyHex)
	if err != nil {
		return err
	}

	sigText := strings.TrimSpace(signatureHex)
	if sigText == "" {
		return errors.New("signature is required")
	}
	sigText = trimHexPrefix(sigText)

	sigBytes, err := hex.DecodeString(sigText)
	if err != nil {
		return errors.New("signature must be hex encoded")
	}
	signature, err := ecdsa.ParseDERSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	return verifySHA256Secp256k1Signature(payload, signature, pubKey)
}

func verifySHA256Secp256k1Signature(payload []byte, signature *ecdsa.Signature, publicKey *secp256k1.PublicKey) error {
	if signature == nil {
		return errors.New("signature is required")
	}
	if publicKey == nil {
		return errors.New("verification key is required")
	}
	hash := sha256.Sum256(payload)
	if !signature.Verify(hash[:], publicKey) {
		return ErrSecp256k1SignatureInvalid
	}
	return nil
}

func ParseSecp256k1PublicKeyHex(raw string) (*secp256k1.PublicKey, error) {
	publicKeyHex := strings.TrimSpace(raw)
	if publicKeyHex == "" {
		return nil, errors.New("public key is required")
	}
	publicKeyHex = trimHexPrefix(publicKeyHex)

	decoded, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, errors.New("public key must be hex encoded")
	}

	publicKey, err := secp256k1.ParsePubKey(decoded)
	if err != nil {
		return nil, errors.New("invalid secp256k1 public key")
	}
	return publicKey, nil
}

func parseSecp256k1PrivateKeyHex(raw string, requireNonZero bool) (*secp256k1.PrivateKey, string, error) {
	privateKeyHex := strings.TrimSpace(raw)
	if privateKeyHex == "" {
		return nil, "", errors.New("private key is required")
	}
	privateKeyHex = trimHexPrefix(privateKeyHex)

	decoded, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, "", errors.New("secp256k1 private key must be hex encoded")
	}
	if len(decoded) != secp256k1.PrivKeyBytesLen {
		return nil, "", fmt.Errorf("secp256k1 private key must be %d bytes", secp256k1.PrivKeyBytesLen)
	}
	if !requireNonZero {
		key := secp256k1.PrivKeyFromBytes(decoded)
		if key == nil {
			return nil, "", errors.New("invalid secp256k1 private key")
		}
		return key, privateKeyHex, nil
	}

	isZero := true
	for _, b := range decoded {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return nil, "", errors.New("secp256k1 private key must not be zero")
	}
	key := secp256k1.PrivKeyFromBytes(decoded)
	if key == nil {
		return nil, "", errors.New("invalid secp256k1 private key")
	}
	return key, privateKeyHex, nil
}

func trimHexPrefix(raw string) string {
	if len(raw) >= 2 && raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X') {
		return raw[2:]
	}
	return raw
}
