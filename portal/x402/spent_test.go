package x402

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	facilitatorcore "github.com/gosuda/x402-facilitator/facilitator"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestSpentDigestsConsumesOnce(t *testing.T) {
	spent := NewSpentDigests("")
	if !spent.Consume("sui:mainnet", "digest-1") {
		t.Fatal("first consume must succeed")
	}
	if spent.Consume("sui:mainnet", "digest-1") {
		t.Fatal("second consume of the same payment must fail")
	}
	if !spent.Consume("sui:mainnet", "digest-2") {
		t.Fatal("a different payment must not be affected")
	}
	if !spent.Consume("sui:testnet", "digest-1") {
		t.Fatal("the same digest on another network is a different payment")
	}
}

func TestSpentDigestsConcurrentReplayGrantsOnce(t *testing.T) {
	spent := NewSpentDigests("")
	const callers = 16
	results := make(chan bool, callers)
	var start sync.WaitGroup
	start.Add(1)
	for range callers {
		go func() {
			start.Wait()
			results <- spent.Consume("sui:mainnet", "digest-race")
		}()
	}
	start.Done()
	granted := 0
	for range callers {
		if <-results {
			granted++
		}
	}
	if granted != 1 {
		t.Fatalf("concurrent replays granted %d times, want exactly 1", granted)
	}
}

func TestSpentDigestsJournalRestoresAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spent.log")
	first := NewSpentDigests(path)
	if !first.Consume("sui:mainnet", "digest-persist") {
		t.Fatal("first consume must succeed")
	}

	restarted := NewSpentDigests(path)
	if restarted.Consume("sui:mainnet", "digest-persist") {
		t.Fatal("a restarted process must reject an already-spent payment")
	}
	if !restarted.Consume("sui:mainnet", "digest-fresh") {
		t.Fatal("a fresh payment after restart must succeed")
	}
}

type replayFacilitator struct{}

func (f *replayFacilitator) Verify(_ context.Context, _ *facilitatortypes.PaymentPayload, _ *facilitatortypes.PaymentRequirements) (*facilitatortypes.PaymentVerifyResponse, error) {
	return &facilitatortypes.PaymentVerifyResponse{IsValid: true}, nil
}

// Settle mimics the vulnerable facilitator behavior: re-presenting the same
// signed payload settles successfully forever.
func (f *replayFacilitator) Settle(_ context.Context, _ *facilitatortypes.PaymentPayload, _ *facilitatortypes.PaymentRequirements) (*facilitatortypes.PaymentSettleResponse, error) {
	return &facilitatortypes.PaymentSettleResponse{
		Success:     true,
		Network:     "sui:mainnet",
		Payer:       "0xpayer",
		Transaction: "digest-replay",
	}, nil
}

func (f *replayFacilitator) Supported() *facilitatortypes.SupportedResponse {
	return &facilitatortypes.SupportedResponse{}
}

var _ facilitatorcore.Facilitator = (*replayFacilitator)(nil)

func TestSettleRejectsReplayedPayment(t *testing.T) {
	payment := &Payment{
		facilitator:  &replayFacilitator{},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
		spent:        NewSpentDigests(""),
	}
	newRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/paid", nil)
		req.Header.Set(types.HeaderXPayment, `{"scheme":"exact"}`)
		return req
	}

	first := httptest.NewRecorder()
	if _, ok := payment.Settle(context.Background(), first, newRequest()); !ok {
		t.Fatalf("first settlement status = %d, want granted", first.Code)
	}
	second := httptest.NewRecorder()
	if _, ok := payment.Settle(context.Background(), second, newRequest()); ok {
		t.Fatal("replayed settlement must be rejected")
	}
	if second.Code != http.StatusPaymentRequired {
		t.Fatalf("replayed settlement status = %d, want %d", second.Code, http.StatusPaymentRequired)
	}
	if body := second.Body.String(); !strings.Contains(body, "payment already redeemed") {
		t.Fatalf("replayed settlement body = %q, want already-redeemed reason", body)
	}
}
