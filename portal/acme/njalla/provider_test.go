package njalla

import (
	"encoding/json"
	"testing"
)

// The njalla API returns record ids as either a JSON string or a JSON number;
// both forms must keep decoding.
func TestRecordIDUnmarshal(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{`{"id":"123"}`, `{"id":123}`} {
		var record record
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
		}
		if record.ID.String() != "123" {
			t.Fatalf("record id = %q, want 123", record.ID.String())
		}
	}
}
