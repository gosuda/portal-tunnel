package gateway

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"slices"
	"strings"

	nanoscheme "github.com/gosuda/x402-facilitator/scheme/nano"
	nanofacilitator "github.com/gosuda/x402-facilitator/scheme/nano/facilitator"
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

// nanoBindingOffer is the requirements.extra.binding a route publishes when
// x402_nano_require_binding is set: the payer signs its block hash with this
// nonce and resource using the key of the paying account, so a block hash seen
// on the public ledger cannot be redeemed here by anyone else. The nonce is
// fresh for each route in each process.
func nanoBindingOffer(resource string) (map[string]any, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("x402 XNO binding nonce: %w", err)
	}
	return map[string]any{
		"scheme":   nanoscheme.BindingScheme,
		"nonce":    hex.EncodeToString(nonce),
		"resource": resource,
	}, nil
}

// openNanoClaimLog opens the claim log at path. A final record that is
// complete but lacks its newline is a spent block, so it is terminated first:
// the facilitator's FileClaimStore drops any final line without a newline as
// a torn write, which would make that block spendable again after the next
// restart. A final line that does not parse is left for the store to drop.
func openNanoClaimLog(path string) (*nanofacilitator.FileClaimStore, error) {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		var last struct {
			Hash string `json:"hash"`
		}
		tail := data[bytes.LastIndexByte(data, '\n')+1:]
		if json.Unmarshal(tail, &last) == nil && last.Hash != "" {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				return nil, err
			}
			_, err = f.Write([]byte{'\n'})
			if err == nil {
				err = f.Sync()
			}
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return nil, err
			}
		}
	}
	return nanofacilitator.NewFileClaimStore(path)
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
