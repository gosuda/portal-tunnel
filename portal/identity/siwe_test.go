package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestSIWEMessageFormat(t *testing.T) {
	// EIP-4361's ABNF defines the literal field order and LF separators:
	// https://eips.ethereum.org/EIPS/eip-4361#message-format
	now := time.Date(2026, 9, 12, 12, 0, 0, 123456789, time.UTC)
	message := types.SIWEMessage{
		Domain: "localhost:8443", Address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
		URI: "https://localhost:8443/login", Statement: "Sign in to Portal",
		Nonce: "32891756", RequestID: "wac_example", IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	want := "localhost:8443 wants you to sign in with your Ethereum account:\n" +
		"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\n\n" +
		"Sign in to Portal\n\n" +
		"URI: https://localhost:8443/login\nVersion: 1\nChain ID: 1\n" +
		"Nonce: 32891756\nIssued At: 2026-09-12T12:00:00Z\n" +
		"Expiration Time: 2026-09-12T12:02:00Z\nRequest ID: wac_example"
	got, err := FormatSIWEMessage(message)
	if err != nil || got != want {
		t.Fatalf("format() = %q, %v; want %q", got, err, want)
	}

	message.Statement = ""
	got, err = FormatSIWEMessage(message)
	want = strings.Replace(want, "Sign in to Portal\n", "", 1)
	if err != nil || got != want {
		t.Fatalf("format without statement = %q, %v; want %q", got, err, want)
	}
}

func TestSIWEMessageRejectsInvalidFields(t *testing.T) {
	for name, change := range map[string]func(*types.SIWEMessage){
		"empty domain":       func(m *types.SIWEMessage) { m.Domain = "" },
		"domain with path":   func(m *types.SIWEMessage) { m.Domain = "example.com/path" },
		"domain with query":  func(m *types.SIWEMessage) { m.Domain = "example.com?" },
		"relative URI":       func(m *types.SIWEMessage) { m.URI = "/login" },
		"invalid address":    func(m *types.SIWEMessage) { m.Address = "0x1234" },
		"statement new line": func(m *types.SIWEMessage) { m.Statement = "Sign in\nNonce: attacker" },
		"short nonce":        func(m *types.SIWEMessage) { m.Nonce = "1234567" },
		"invalid nonce":      func(m *types.SIWEMessage) { m.Nonce = "1234567_" },
		"request ID line":    func(m *types.SIWEMessage) { m.RequestID = "id\r\nResources:" },
	} {
		t.Run(name, func(t *testing.T) {
			message := types.SIWEMessage{
				Domain: "example.com", Address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
				URI: "https://example.com/login", Nonce: "32891756", RequestID: "wac_example",
				IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
			}
			change(&message)
			if _, err := FormatSIWEMessage(message); err == nil {
				t.Fatal("invalid SIWE field accepted")
			}
		})
	}
}

func TestEthereumPersonalMessageRecoveryVectors(t *testing.T) {
	// Independent signatures from Spruce's SIWE interoperability vectors:
	// https://github.com/spruceid/siwe/blob/911f6f2c73ef24deac73fec2f6b84930721d2fb4/test/verification_positive.json
	// Keep the signed bytes literal, including fractional seconds. Recovery does
	// not parse or rewrite the message, or depend on Portal's signing function.
	for _, test := range []struct {
		name, message, signature, address string
	}{
		{
			name: "example message",
			message: "login.xyz wants you to sign in with your Ethereum account:\n" +
				"0x9D85ca56217D2bb651b00f15e694EB7E713637D4\n\n" +
				"Sign-In With Ethereum Example Statement\n\n" +
				"URI: https://login.xyz\nVersion: 1\nChain ID: 1\nNonce: bTyXgcQxn2htgkjJn\n" +
				"Issued At: 2022-01-27T17:09:38.578Z\nExpiration Time: 2100-01-07T14:31:43.952Z",
			signature: "0xdc35c7f8ba2720df052e0092556456127f00f7707eaa8e3bbff7e56774e7f2e05a093cfc9e02964c33d86e8e066e221b7d153d27e5a2e97ccd5ca7d3f2ce06cb1b",
			address:   "0x9D85ca56217D2bb651b00f15e694EB7E713637D4",
		},
		{
			name: "normalized recovery byte",
			message: "www.tally.xyz wants you to sign in with your Ethereum account:\n" +
				"0xc95EB884FE852e241D409234bfC7045CB9E31BD7\n\n" +
				"Sign in with Ethereum to Tally\n\n" +
				"URI: https://tally.xyz\nVersion: 1\nChain ID: 1\nNonce: 15050747\n" +
				"Issued At: 2022-06-30T14:08:51.382Z",
			signature: "0x8c46b6eb8505939892d8e9b075f89f8277321b17b993151f37810cdda38cce6f4a85909d2b53e6a14629c74c0ac38bf4becde78ee5b2529812bf6cceaf7b2a2501",
			address:   "0xc95EB884FE852e241D409234bfC7045CB9E31BD7",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			alternate := test.signature[:130] + "00"
			if strings.HasSuffix(test.signature, "01") {
				alternate = test.signature[:130] + "1c"
			}
			for _, signature := range []string{test.signature, alternate} {
				address, err := recoverEthereumPersonalMessage(test.message, signature)
				if err != nil || address != test.address {
					t.Fatalf("recover = %q, %v; want %q", address, err, test.address)
				}
			}
			address, err := recoverEthereumPersonalMessage(test.message+"!", test.signature)
			if err == nil && address == test.address {
				t.Fatal("signature authenticated a changed message")
			}
		})
	}
}

func TestEthereumPersonalMessageRejectsMalformedSignatures(t *testing.T) {
	valid := "dc35c7f8ba2720df052e0092556456127f00f7707eaa8e3bbff7e56774e7f2e05a093cfc9e02964c33d86e8e066e221b7d153d27e5a2e97ccd5ca7d3f2ce06cb1b"
	for name, signature := range map[string]string{
		"empty": "", "short": "0x12", "long": "0x" + valid + "00", "missing prefix": valid,
		"non hex":        "0xzz" + valid[2:],
		"zero r and s":   "0x" + strings.Repeat("00", 64) + "1b",
		"overflow r":     "0x" + strings.Repeat("ff", 32) + valid[64:],
		"overflow s":     "0x" + valid[:64] + strings.Repeat("ff", 32) + "1b",
		"invalid v":      "0x" + valid[:128] + "02",
		"transaction v":  "0x" + valid[:128] + "25",
		"v modulo alias": "0x" + valid[:128] + "36",
		"compact header": "0x" + valid[:128] + "1f",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := recoverEthereumPersonalMessage("message", signature); err == nil {
				t.Fatal("malformed personal-sign signature accepted")
			}
		})
	}
}
