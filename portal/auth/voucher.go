package auth

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// SignReservationVoucher returns a copy of v with its Signature field populated
// by signing CanonicalBytes() with the supplied secp256k1 private key (hex
// encoded). The signature is recoverable, so verifiers do not need the public
// key out of band; they recover it from the signature and check it against the
// expected relay address.
//
// EXPERIMENTAL: see documentation note on types.ReservationVoucher.
func SignReservationVoucher(v types.ReservationVoucher, privateKeyHex string) (types.ReservationVoucher, error) {
	privateKey, _, err := utils.ParseSecp256k1PrivateKeyHex(privateKeyHex, true)
	if err != nil {
		return types.ReservationVoucher{}, fmt.Errorf("reservation voucher signing key: %w", err)
	}

	v.Signature = nil
	canonical := v.CanonicalBytes()

	signature, err := utils.SignSHA256Secp256k1Compact(canonical, privateKey, true)
	if err != nil {
		return types.ReservationVoucher{}, fmt.Errorf("sign reservation voucher: %w", err)
	}

	v.Signature = signature
	return v, nil
}

// VerifyReservationVoucher checks the voucher's Signature against its
// CanonicalBytes() and confirms that the recovered signing key corresponds to
// expectedAddress (the relay's secp256k1 address from its RelayDescriptor).
// Returns nil on success.
//
// EXPERIMENTAL: see documentation note on types.ReservationVoucher.
func VerifyReservationVoucher(v types.ReservationVoucher, expectedAddress string) error {
	if len(v.Signature) == 0 {
		return errors.New("reservation voucher is not signed")
	}

	// Build unsigned copy for canonical bytes computation.
	unsigned := v
	unsigned.Signature = nil
	canonical := unsigned.CanonicalBytes()

	publicKey, err := utils.RecoverSHA256Secp256k1Compact(canonical, v.Signature)
	if err != nil {
		return fmt.Errorf("reservation voucher signature is invalid: %w", err)
	}

	publicKeyHex := hex.EncodeToString(publicKey.SerializeCompressed())
	derivedAddress, err := utils.AddressFromCompressedPublicKeyHex(publicKeyHex)
	if err != nil {
		return fmt.Errorf("derive address from recovered key: %w", err)
	}

	if !strings.EqualFold(strings.TrimSpace(derivedAddress), strings.TrimSpace(expectedAddress)) {
		return errors.New("reservation voucher address does not match recovered signing key")
	}
	return nil
}

// VerifyReservationVoucherFromDescriptor is a convenience wrapper that extracts
// the expected relay address from a descriptor and delegates to
// VerifyReservationVoucher.
//
// EXPERIMENTAL: see documentation note on types.ReservationVoucher.
func VerifyReservationVoucherFromDescriptor(v types.ReservationVoucher, desc types.RelayDescriptor) error {
	return VerifyReservationVoucher(v, desc.Address)
}

// ReservationVoucherSignatureBase64 returns the voucher Signature field encoded
// as standard base64. Provided as a convenience for HTTP response serialisation
// where the caller wants a string representation rather than raw bytes.
// The ReservationVoucher.Signature field itself already round-trips through
// encoding/json as base64 automatically ([]byte JSON encoding).
func ReservationVoucherSignatureBase64(v types.ReservationVoucher) string {
	return base64.StdEncoding.EncodeToString(v.Signature)
}
