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
	spent, err := NewSpentDigests("")
	if err != nil {
		t.Fatalf("NewSpentDigests() error = %v", err)
	}
	if ok, err := spent.Consume("sui:mainnet", "digest-1"); err != nil || !ok {
		t.Fatalf("first consume = %v/%v, want true/nil", ok, err)
	}
	if ok, err := spent.Consume("sui:mainnet", "digest-1"); err != nil || ok {
		t.Fatalf("second consume of the same payment = %v/%v, want false/nil", ok, err)
	}
	if ok, err := spent.Consume("sui:mainnet", "digest-2"); err != nil || !ok {
		t.Fatalf("a different payment = %v/%v, want true/nil", ok, err)
	}
	if ok, err := spent.Consume("sui:testnet", "digest-1"); err != nil || !ok {
		t.Fatalf("the same digest on another network = %v/%v, want true/nil", ok, err)
	}
	if ok, err := spent.Consume("sui:mainnet", "  "); err != nil || ok {
		t.Fatalf("an empty digest = %v/%v, want false/nil", ok, err)
	}
}

func TestSpentDigestsConcurrentReplayGrantsOnce(t *testing.T) {
	spent, err := NewSpentDigests("")
	if err != nil {
		t.Fatalf("NewSpentDigests() error = %v", err)
	}
	const callers = 16
	results := make(chan bool, callers)
	var start sync.WaitGroup
	start.Add(1)
	for range callers {
		go func() {
			start.Wait()
			ok, err := spent.Consume("sui:mainnet", "digest-race")
			results <- err == nil && ok
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
	first, err := NewSpentDigests(path)
	if err != nil {
		t.Fatalf("NewSpentDigests() error = %v", err)
	}
	if ok, err := first.Consume("sui:mainnet", "digest-persist"); err != nil || !ok {
		t.Fatalf("first consume = %v/%v, want true/nil", ok, err)
	}

	restarted, err := NewSpentDigests(path)
	if err != nil {
		t.Fatalf("NewSpentDigests(restart) error = %v", err)
	}
	if ok, err := restarted.Consume("sui:mainnet", "digest-persist"); err != nil || ok {
		t.Fatal("a restarted process must reject an already-spent payment")
	}
	if ok, err := restarted.Consume("sui:mainnet", "digest-fresh"); err != nil || !ok {
		t.Fatal("a fresh payment after restart must succeed")
	}
	_ = first.Close()
	_ = restarted.Close()
}

func TestSpentDigestsJournalAppendFailureFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spent.log")
	spent, err := NewSpentDigests(path)
	if err != nil {
		t.Fatalf("NewSpentDigests() error = %v", err)
	}
	if err := spent.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if ok, err := spent.Consume("sui:mainnet", "digest-unwritable"); err == nil || ok {
		t.Fatalf("consume with a broken journal = %v/%v, want false/error", ok, err)
	}
}

type replayFacilitator struct {
	transaction string
}

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
		Transaction: f.transaction,
	}, nil
}

func (f *replayFacilitator) Supported() *facilitatortypes.SupportedResponse {
	return &facilitatortypes.SupportedResponse{}
}

var _ facilitatorcore.Facilitator = (*replayFacilitator)(nil)

func newPaidRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/paid", nil)
	req.Header.Set(types.HeaderXPayment, `{"scheme":"exact"}`)
	return req
}

func TestSettleRejectsReplayedPayment(t *testing.T) {
	payment := &Payment{
		facilitator:  &replayFacilitator{transaction: "digest-replay"},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
		spent:        newMemorySpentDigests(t),
	}

	first := httptest.NewRecorder()
	if _, ok := payment.Settle(context.Background(), first, newPaidRequest()); !ok {
		t.Fatalf("first settlement status = %d, want granted", first.Code)
	}
	second := httptest.NewRecorder()
	if _, ok := payment.Settle(context.Background(), second, newPaidRequest()); ok {
		t.Fatal("replayed settlement must be rejected")
	}
	if second.Code != http.StatusPaymentRequired {
		t.Fatalf("replayed settlement status = %d, want %d", second.Code, http.StatusPaymentRequired)
	}
	if body := second.Body.String(); !strings.Contains(body, "payment already redeemed") {
		t.Fatalf("replayed settlement body = %q, want already-redeemed reason", body)
	}
}

func TestSharedSpentStoreRejectsCrossRouteReplay(t *testing.T) {
	// Two paid routes of one HTTP surface share a single store: the same
	// settlement digest must grant exactly one route.
	shared := newMemorySpentDigests(t)
	routeA := &Payment{
		facilitator:  &replayFacilitator{transaction: "digest-shared"},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
		spent:        shared,
	}
	routeB := &Payment{
		facilitator:  &replayFacilitator{transaction: "digest-shared"},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
		spent:        shared,
	}

	recorderA := httptest.NewRecorder()
	if _, ok := routeA.Settle(context.Background(), recorderA, newPaidRequest()); !ok {
		t.Fatalf("route A settlement status = %d, want granted", recorderA.Code)
	}
	recorderB := httptest.NewRecorder()
	if _, ok := routeB.Settle(context.Background(), recorderB, newPaidRequest()); ok {
		t.Fatal("the same payment replayed on route B must be rejected")
	}
	if recorderB.Code != http.StatusPaymentRequired {
		t.Fatalf("route B replay status = %d, want %d", recorderB.Code, http.StatusPaymentRequired)
	}
}

func TestSettleRejectsEmptyTransactionDigest(t *testing.T) {
	payment := &Payment{
		facilitator:  &replayFacilitator{transaction: "  "},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
		spent:        newMemorySpentDigests(t),
	}

	recorder := httptest.NewRecorder()
	if _, ok := payment.Settle(context.Background(), recorder, newPaidRequest()); ok {
		t.Fatal("a settlement without a transaction digest must be rejected")
	}
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("empty-digest settlement status = %d, want %d", recorder.Code, http.StatusPaymentRequired)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "missing transaction digest") {
		t.Fatalf("empty-digest settlement body = %q, want missing-digest reason", body)
	}
}

func TestSettleRejectsMissingSpentStore(t *testing.T) {
	payment := &Payment{
		facilitator:  &replayFacilitator{transaction: "digest-no-store"},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
	}
	recorder := httptest.NewRecorder()
	if _, ok := payment.Settle(context.Background(), recorder, newPaidRequest()); ok {
		t.Fatal("a settlement without a spent-digest store must be rejected")
	}
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("missing-store settlement status = %d, want %d", recorder.Code, http.StatusPaymentRequired)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "replay tracking unavailable") {
		t.Fatalf("missing-store settlement body = %q, want unavailable reason", body)
	}
}

func TestSettleReplayRejectedAfterReconstruction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spent.log")

	first, err := NewSpentDigests(path)
	if err != nil {
		t.Fatalf("NewSpentDigests() error = %v", err)
	}
	original := &Payment{
		facilitator:  &replayFacilitator{transaction: "digest-reconstruct"},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
		spent:        first,
	}
	recorder := httptest.NewRecorder()
	if _, ok := original.Settle(context.Background(), recorder, newPaidRequest()); !ok {
		t.Fatalf("original settlement status = %d, want granted", recorder.Code)
	}

	reconstructed, err := NewSpentDigests(path)
	if err != nil {
		t.Fatalf("NewSpentDigests(reconstruct) error = %v", err)
	}
	rebuilt := &Payment{
		facilitator:  &replayFacilitator{transaction: "digest-reconstruct"},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
		spent:        reconstructed,
	}
	replay := httptest.NewRecorder()
	if _, ok := rebuilt.Settle(context.Background(), replay, newPaidRequest()); ok {
		t.Fatal("a payment replayed after full reconstruction must be rejected")
	}
	if replay.Code != http.StatusPaymentRequired {
		t.Fatalf("post-reconstruction replay status = %d, want %d", replay.Code, http.StatusPaymentRequired)
	}
	_ = first.Close()
	_ = reconstructed.Close()
}

func TestSettleRejectsWhenJournalAppendFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spent.log")
	spent, err := NewSpentDigests(path)
	if err != nil {
		t.Fatalf("NewSpentDigests() error = %v", err)
	}
	payment := &Payment{
		facilitator:  &replayFacilitator{transaction: "digest-journal-fail"},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
		spent:        spent,
	}

	if err := spent.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	if _, ok := payment.Settle(context.Background(), recorder, newPaidRequest()); ok {
		t.Fatal("a settlement whose journal append failed must be rejected")
	}
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("journal-failure settlement status = %d, want %d", recorder.Code, http.StatusPaymentRequired)
	}
}

func newMemorySpentDigests(t *testing.T) *SpentDigests {
	t.Helper()
	spent, err := NewSpentDigests("")
	if err != nil {
		t.Fatalf("NewSpentDigests() error = %v", err)
	}
	return spent
}
