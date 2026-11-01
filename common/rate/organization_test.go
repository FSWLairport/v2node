package rate

import "testing"

func TestOrganizationBucketsShareOnlyWithinDirectionAndOrganization(t *testing.T) {
	l := NewOrganizationLimiter(map[int]BandwidthLimit{7: {UpMbps: 1, DownMbps: 2}, 8: {UpMbps: 1}})
	up, down := l.Buckets(7)
	same, _ := l.Buckets(7)
	other, unlimitedDown := l.Buckets(8)
	if same != up || up == down || other == up || unlimitedDown != nil {
		t.Fatal("incorrect bucket scopes")
	}
	up.Get().Take(1250000)
	if AllowBytes(same, 64000) {
		t.Fatal("shared upload cap not enforced")
	}
	if !AllowBytes(down, 250000) || !AllowBytes(other, 125000) {
		t.Fatal("one tenant or direction consumed another's allowance")
	}
	missingUp, missingDown := l.Buckets(99)
	if missingUp != nil || missingDown != nil || !AllowBytes(nil, 1000000) {
		t.Fatal("missing limits must be unlimited")
	}
}

func TestValidateBandwidthLimits(t *testing.T) {
	for _, limits := range []map[int]BandwidthLimit{{0: {UpMbps: 1}}, {1: {UpMbps: -1}}, {1: {DownMbps: 1000001}}} {
		if ValidateBandwidthLimits(limits) == nil {
			t.Fatalf("accepted invalid limits: %v", limits)
		}
	}
	if err := ValidateBandwidthLimits(map[int]BandwidthLimit{1: {UpMbps: 1000000}}); err != nil {
		t.Fatal(err)
	}
}
