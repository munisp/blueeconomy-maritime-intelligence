package incident

import (
	"testing"
	"time"
)

// TestValidateFeedFreshness is the M8 regression: signed feed events carry a
// claimed_at timestamp and stale or far-future claims are rejected.
func TestValidateFeedFreshness(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		claimedAt time.Time
		wantErr   bool
	}{
		{"now", now, false},
		{"inside window", now.Add(-FeedReplayWindow + time.Minute), false},
		{"inside skew", now.Add(FeedClockSkew - time.Minute), false},
		{"stale replay", now.Add(-FeedReplayWindow - time.Minute), true},
		{"far future", now.Add(FeedClockSkew + time.Minute), true},
		{"zero", time.Time{}, true},
	} {
		err := ValidateFeedFreshness(test.claimedAt, now)
		if (err != nil) != test.wantErr {
			t.Fatalf("%s: ValidateFeedFreshness err=%v, wantErr=%v", test.name, err, test.wantErr)
		}
	}
}

// TestFeedSigningBytesBindsClaimedAt ensures the claimed_at timestamp is part
// of the signing preimage, so a signature cannot be re-dated.
func TestFeedSigningBytesBindsClaimedAt(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	payload := []byte("payload")
	first := FeedSigningBytes("ais-1", "evt-1", now, payload)
	second := FeedSigningBytes("ais-1", "evt-1", now.Add(time.Second), payload)
	if string(first) == string(second) {
		t.Fatal("signing preimage must change with claimed_at")
	}
	third := FeedSigningBytes("ais-1", "evt-1", now, payload)
	if string(first) != string(third) {
		t.Fatal("signing preimage must be deterministic")
	}
}
