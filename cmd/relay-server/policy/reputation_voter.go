package policy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
)

func (s *ReputationStore) ensureVoterSecret() error {
	if len(s.state.VoterSecret) == 0 {
		s.state.VoterSecret = make([]byte, reputationVoterIDBytes)
		if _, err := rand.Read(s.state.VoterSecret); err != nil {
			return fmt.Errorf("generate reputation voter secret: %w", err)
		}
	}
	return nil
}

func (s *ReputationStore) resolveVoterLocked(cookieID string, source netip.Addr) (hash, minted string, err error) {
	if cookieID != "" {
		if verified, ok := s.verifyVoter(cookieID); ok {
			return verified, "", nil
		}
	}
	if !source.IsValid() {
		return "", "", ErrReputationCapacity
	}
	sourceMAC := hmac.New(sha256.New, s.secret)
	_, _ = sourceMAC.Write([]byte("reputation-source-v1\x00"))
	_, _ = sourceMAC.Write(source.Unmap().AsSlice())
	id := sourceMAC.Sum(nil)
	digest := s.voterMAC(id)
	hash = hex.EncodeToString(digest)
	return hash, base64.RawURLEncoding.EncodeToString(append(id, digest...)), nil
}

func (s *ReputationStore) verifyVoter(cookieID string) (string, bool) {
	value, err := base64.RawURLEncoding.DecodeString(cookieID)
	if err != nil || len(value) != reputationVoterIDBytes+sha256.Size {
		return "", false
	}
	expected := s.voterMAC(value[:reputationVoterIDBytes])
	if subtle.ConstantTimeCompare(expected, value[reputationVoterIDBytes:]) != 1 {
		return "", false
	}
	return hex.EncodeToString(expected), true
}

func (s *ReputationStore) voterMAC(id []byte) []byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(id)
	return mac.Sum(nil)
}
