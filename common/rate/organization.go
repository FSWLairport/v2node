package rate

import (
	"fmt"
	"github.com/juju/ratelimit"
)

// BandwidthLimit is per organization on one node, from the client's direction.
type BandwidthLimit struct {
	UpMbps   int `json:"up_mbps"`
	DownMbps int `json:"down_mbps"`
}

type OrganizationLimiter struct{ buckets map[int][2]*DynamicBucket }

func ValidateBandwidthLimits(limits map[int]BandwidthLimit) error {
	for org, limit := range limits {
		if org <= 0 || limit.UpMbps < 0 || limit.DownMbps < 0 || limit.UpMbps > 1000000 || limit.DownMbps > 1000000 {
			return fmt.Errorf("invalid bandwidth limit for organization %d", org)
		}
	}
	return nil
}

func NewOrganizationLimiter(limits map[int]BandwidthLimit) *OrganizationLimiter {
	l := &OrganizationLimiter{buckets: make(map[int][2]*DynamicBucket, len(limits))}
	for org, limit := range limits {
		l.buckets[org] = [2]*DynamicBucket{NewBandwidthBucket(limit.UpMbps), NewBandwidthBucket(limit.DownMbps)}
	}
	return l
}

func NewBandwidthBucket(mbps int) *DynamicBucket {
	if mbps <= 0 {
		return nil
	}
	// Refill continuously: packet policing must not stall a tenant until the next whole second.
	bytesPerSecond := int64(mbps) * 1000000 / 8
	bucket := &DynamicBucket{}
	bucket.v.Store(ratelimit.NewBucketWithRate(float64(bytesPerSecond), bytesPerSecond))
	return bucket
}

func (l *OrganizationLimiter) Buckets(org int) (up, down *DynamicBucket) {
	if l == nil {
		return nil, nil
	}
	b := l.buckets[org]
	return b[0], b[1]
}

// AllowBytes polices packets without sleeping on the shared TUN path.
func AllowBytes(bucket *DynamicBucket, size int) bool {
	if bucket == nil {
		return true
	}
	_, ok := bucket.Get().TakeMaxDuration(int64(size), 0)
	return ok
}
