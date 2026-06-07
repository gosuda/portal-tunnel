package identity

import (
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/sha3"
)

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

func trimHexPrefix(raw string) string {
	if len(raw) >= 2 && raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X') {
		return raw[2:]
	}
	return raw
}
