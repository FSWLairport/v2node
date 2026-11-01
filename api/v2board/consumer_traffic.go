package panel

import (
	"context"
	"fmt"
	"time"

	"encoding/json/v2"
)

type ConsumerTrafficSample struct {
	LeaseID  string `json:"lease_id"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}
type ConsumerTrafficBatch struct {
	ID         string                  `json:"id"`
	ObservedAt time.Time               `json:"observed_at"`
	Samples    []ConsumerTrafficSample `json:"samples"`
}

func (c *Client) ReportConsumerTraffic(ctx context.Context, batch ConsumerTrafficBatch) error {
	response, err := c.client.R().SetContext(ctx).SetBody(batch).ForceContentType("application/json").Post("/api/v1/server/UniProxy/consumer-traffic")
	if err != nil {
		return err
	}
	if response == nil || response.StatusCode() < 200 || response.StatusCode() >= 300 {
		return fmt.Errorf("consumer traffic was not acknowledged")
	}
	var result struct {
		Accepted int `json:"accepted"`
	}
	if err = json.Unmarshal(response.Body(), &result); err != nil || result.Accepted != len(batch.Samples) {
		return fmt.Errorf("invalid consumer traffic acknowledgement")
	}
	return nil
}
