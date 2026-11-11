package gateway

import (
	"cmp"
	"fmt"
	"math/big"
	"slices"
	"strings"

	nanoscheme "github.com/gosuda/x402-facilitator/scheme/nano"
	"golang.org/x/crypto/blake2b"
)

const nanoAddressAlphabet = "13456789abcdefghijkmnopqrstuwxyz"

func normalizeNanoAddress(address string) string {
	address = strings.ToLower(strings.TrimSpace(address))
	encoded, ok := strings.CutPrefix(address, "nano_")
	if !ok {
		encoded, ok = strings.CutPrefix(address, "xrb_")
	}
	if !ok {
		return ""
	}
	if len(encoded) != 60 {
		return ""
	}
	bits := new(big.Int)
	for i := range len(encoded) {
		value := strings.IndexByte(nanoAddressAlphabet, encoded[i])
		if value < 0 {
			return ""
		}
		bits.Lsh(bits, 5).Or(bits, big.NewInt(int64(value)))
	}
	decoded := bits.FillBytes(make([]byte, 38))
	if decoded[0] != 0 {
		return ""
	}
	hash, err := blake2b.New(5, nil)
	if err != nil {
		return ""
	}
	_, _ = hash.Write(decoded[1:33])
	checksum := hash.Sum(nil)
	slices.Reverse(checksum)
	if string(checksum) != string(decoded[33:]) {
		return ""
	}
	return "nano_" + encoded
}

func xnoToRaw(amount string) (string, error) {
	amount = strings.TrimSpace(amount)
	whole, frac, _ := strings.Cut(amount, ".")
	whole = cmp.Or(whole, "0")
	fracValid := frac == "" || isDecimalDigits(frac)
	if !isDecimalDigits(whole) || !fracValid || strings.HasSuffix(amount, ".") {
		return "", fmt.Errorf("invalid XNO amount %q", amount)
	}
	if len(frac) > nanoscheme.XNORawDecimals {
		return "", fmt.Errorf("XNO amount %q has more than %d decimals", amount, nanoscheme.XNORawDecimals)
	}
	raw, ok := new(big.Int).SetString(whole+frac+strings.Repeat("0", nanoscheme.XNORawDecimals-len(frac)), 10)
	if !ok || raw.Sign() <= 0 {
		return "", fmt.Errorf("invalid XNO amount %q", amount)
	}
	return raw.String(), nil
}

func isDecimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}
