package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	// CompactSecp256k1SignatureSize is the byte length of a compact
	// recoverable secp256k1 ECDSA signature.
	CompactSecp256k1SignatureSize = 65
	// RawSecp256k1SignatureSize is the byte length of the JOSE ES256K
	// signature form, r || s with no recovery header.
	RawSecp256k1SignatureSize = 64
)

// ErrSecp256k1SignatureInvalid marks a well-formed signature that does not
// verify for the payload and public key.
var ErrSecp256k1SignatureInvalid = errors.New("signature is invalid")

func NormalizeEVMAddress(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("address is required")
	}
	hexPart := TrimHexPrefix(trimmed)
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

func SignEthereumPersonalMessage(message, privateKeyHex string) (string, error) {
	privateKey, _, err := ParseSecp256k1PrivateKeyHex(privateKeyHex, false)
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

	privateKey, normalizedKeyHex, err := ParseSecp256k1PrivateKeyHex(privateKeyHex, true)
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

func SignSHA256Secp256k1DER(payload []byte, privateKeyHex string) (string, error) {
	privateKey, _, err := ParseSecp256k1PrivateKeyHex(privateKeyHex, false)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(payload)
	signature := ecdsa.Sign(privateKey, hash[:])
	return hex.EncodeToString(signature.Serialize()), nil
}

// SignSHA256Secp256k1Compact signs the SHA-256 digest of payload and returns
// the compact recoverable secp256k1 ECDSA signature.
func SignSHA256Secp256k1Compact(payload []byte, privateKey *secp256k1.PrivateKey, compressed bool) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("signing key is required")
	}
	hash := sha256.Sum256(payload)
	signature := ecdsa.SignCompact(privateKey, hash[:], compressed)
	if len(signature) != CompactSecp256k1SignatureSize {
		return nil, errors.New("invalid compact signature length")
	}
	return signature, nil
}

// SignSHA256Secp256k1Raw64 signs the SHA-256 digest of payload and returns
// the raw r || s signature form used by ES256K.
func SignSHA256Secp256k1Raw64(payload []byte, privateKey *secp256k1.PrivateKey) ([]byte, error) {
	compact, err := SignSHA256Secp256k1Compact(payload, privateKey, false)
	if err != nil {
		return nil, err
	}

	signature := make([]byte, RawSecp256k1SignatureSize)
	copy(signature[:32], compact[1:33])
	copy(signature[32:], compact[33:65])
	return signature, nil
}

// RecoverSHA256Secp256k1Compact recovers the public key from a compact
// recoverable signature over the SHA-256 digest of payload.
func RecoverSHA256Secp256k1Compact(payload, signature []byte) (*secp256k1.PublicKey, error) {
	if len(signature) != CompactSecp256k1SignatureSize {
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
	if len(signature) != RawSecp256k1SignatureSize {
		return errors.New("invalid es256k signature length")
	}

	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(signature[:32]); overflow || r.IsZero() {
		return errors.New("invalid es256k signature r")
	}
	if overflow := s.SetByteSlice(signature[32:]); overflow || s.IsZero() {
		return errors.New("invalid es256k signature s")
	}

	return verifySHA256Secp256k1Signature(payload, ecdsa.NewSignature(&r, &s), publicKey)
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
	sigText = TrimHexPrefix(sigText)

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

func NormalizeWireGuardPrivateKey(raw string) (string, error) {
	key, err := decodeWireGuardKey(raw)
	if err != nil {
		return "", err
	}
	clampWireGuardPrivateKey(&key)
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

func GenerateWireGuardPrivateKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	clampWireGuardPrivateKey(&key)
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

func WireGuardPublicKeyFromPrivate(raw string) (string, error) {
	privateKey, err := decodeWireGuardKey(raw)
	if err != nil {
		return "", err
	}
	clampWireGuardPrivateKey(&privateKey)
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return base64.StdEncoding.EncodeToString(publicKey[:]), nil
}

func WireGuardListenPort(rawEndpoint string) (int, error) {
	endpoint := strings.TrimSpace(rawEndpoint)
	if endpoint == "" {
		return 0, errors.New("wireguard endpoint is required")
	}
	_, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0, errors.New("wireguard endpoint must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return 0, errors.New("wireguard endpoint port is invalid")
	}
	return port, nil
}

func DeriveWireGuardOverlayIPv4(publicKey string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil {
		return "", errors.New("wireguard public key must be base64 encoded")
	}
	if len(decoded) != 32 {
		return "", errors.New("wireguard public key must be 32 bytes")
	}

	sum := sha256.Sum256(decoded)
	return netip.AddrFrom4([4]byte{
		100,
		64 + (sum[0] & 0x3f),
		sum[1],
		1 + (sum[2] % 254),
	}).String(), nil
}

func WireGuardKeyHex(raw string) (string, error) {
	key, err := decodeWireGuardKey(raw)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key[:]), nil
}

func decodeWireGuardKey(raw string) ([32]byte, error) {
	var key [32]byte
	value := strings.TrimSpace(raw)
	if value == "" {
		return key, errors.New("wireguard key is required")
	}

	var decoded []byte
	var err error
	if len(value) == 64 && !strings.Contains(value, "=") {
		decoded, err = hex.DecodeString(value)
	} else {
		decoded, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil {
		return key, errors.New("wireguard key must be base64 or hex encoded")
	}
	if len(decoded) != len(key) {
		return key, errors.New("wireguard key must be 32 bytes")
	}
	copy(key[:], decoded)
	return key, nil
}

func clampWireGuardPrivateKey(key *[32]byte) {
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
}

func ValidateWireGuardPublicKey(raw string) error {
	key := strings.TrimSpace(raw)
	if key == "" {
		return errors.New("wireguard_public_key is required")
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return errors.New("wireguard_public_key must be base64 encoded")
	}
	if len(decoded) != 32 {
		return errors.New("wireguard_public_key must be 32 bytes")
	}
	return nil
}

func ValidateWireGuardEndpoint(raw string) error {
	endpoint := strings.TrimSpace(raw)
	if endpoint == "" {
		return errors.New("wireguard_endpoint is required")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return errors.New("wireguard_endpoint must be host:port")
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("wireguard_endpoint host is required")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return errors.New("wireguard_endpoint port is invalid")
	}
	return nil
}

func ValidateOverlayIPv4(raw string) error {
	ipText := strings.TrimSpace(raw)
	if ipText == "" {
		return errors.New("overlay_ipv4 is required")
	}
	ip := net.ParseIP(ipText)
	if ip == nil || ip.To4() == nil {
		return errors.New("overlay_ipv4 must be a valid IPv4 address")
	}
	return nil
}

func NormalizeOverlayCIDRs(inputs []string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(inputs))
	out := make([]string, 0, len(inputs))
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		_, network, err := net.ParseCIDR(input)
		if err != nil {
			return nil, fmt.Errorf("invalid overlay cidr %q", input)
		}
		normalized := network.String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out, nil
}

func ParseSecp256k1PublicKeyHex(raw string) (*secp256k1.PublicKey, error) {
	publicKeyHex := strings.TrimSpace(raw)
	if publicKeyHex == "" {
		return nil, errors.New("public key is required")
	}
	publicKeyHex = TrimHexPrefix(publicKeyHex)

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

func ParseSecp256k1PrivateKeyHex(raw string, requireNonZero bool) (*secp256k1.PrivateKey, string, error) {
	privateKeyHex := strings.TrimSpace(raw)
	if privateKeyHex == "" {
		return nil, "", errors.New("private key is required")
	}
	privateKeyHex = TrimHexPrefix(privateKeyHex)

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
