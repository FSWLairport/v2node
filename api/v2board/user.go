package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
)

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id          int    `json:"id" msgpack:"id"`
	Uuid        string `json:"uuid" msgpack:"uuid"`
	SpeedLimit  int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit int    `json:"device_limit" msgpack:"device_limit"`
	GroupID     int    `json:"group_id" msgpack:"group_id"`
}

type UserListBody struct {
	Users []UserInfo `json:"users" msgpack:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

// GetUserList will pull user from v2board
func (c *Client) GetUserList(ctx context.Context) ([]UserInfo, error) {
	const path = "/api/v1/server/UniProxy/user"
	r, err := c.client.R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.userEtag).
		SetHeader("X-Response-Format", "msgpack").
		SetDoNotParseResponse(true).
		Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("received nil response or raw response")
	}
	defer r.RawResponse.Body.Close()

	if r.StatusCode() == 304 {
		return nil, nil
	}
	// An empty list is now actionable (it removes every credential on the node),
	// so an error response must never reach the decoder and be read as "no users".
	if r.StatusCode() < 200 || r.StatusCode() >= 300 {
		return nil, fmt.Errorf("get user list: unexpected status %d", r.StatusCode())
	}
	// Keep a successful 200 {"users":[]} distinguishable from 304, for which
	// this method returns a nil slice. The distinction is required to revoke the
	// final credential on a node.
	userlist := &UserListBody{Users: make([]UserInfo, 0)}
	if strings.Contains(r.Header().Get("Content-Type"), "application/x-msgpack") {
		decoder := msgpack.NewDecoder(r.RawResponse.Body)
		if err := decoder.Decode(userlist); err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
		if userlist.Users == nil {
			userlist.Users = make([]UserInfo, 0)
		}
	} else {
		dec := jsontext.NewDecoder(r.RawResponse.Body)
		for {
			tok, err := dec.ReadToken()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: %w", err)
			}
			if tok.Kind() == '"' && tok.String() == "users" {
				break
			}
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
		if tok.Kind() != '[' {
			return nil, fmt.Errorf(`decode user list error: expected "users" array`)
		}
		for dec.PeekKind() != ']' {
			val, err := dec.ReadValue()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: read user object: %w", err)
			}
			var u UserInfo
			if err := json.Unmarshal(val, &u); err != nil {
				return nil, fmt.Errorf("decode user list error: unmarshal user error: %w", err)
			}
			userlist.Users = append(userlist.Users, u)
		}
	}
	c.userEtag = r.Header().Get("ETag")
	return userlist.Users, nil
}

// GetUserAlive will fetch the alive_ip count for users
func (c *Client) GetUserAlive(ctx context.Context) (map[int]int, error) {
	c.AliveMap = &AliveMap{}
	const path = "/api/v1/server/UniProxy/alivelist"
	r, err := c.client.R().
		SetContext(ctx).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		c.AliveMap.Alive = make(map[int]int)
		return c.AliveMap.Alive, nil
	}
	if r == nil || r.RawResponse == nil || r.StatusCode() >= 399 {
		c.AliveMap.Alive = make(map[int]int)
		return c.AliveMap.Alive, nil
	}
	defer r.RawResponse.Body.Close()
	if err := json.Unmarshal(r.Body(), c.AliveMap); err != nil {
		fmt.Printf("unmarshal user alive list error: %s", err)
		c.AliveMap.Alive = make(map[int]int)
	}

	return c.AliveMap.Alive, nil
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

// ReportUserTraffic reports the user traffic
func (c *Client) ReportUserTraffic(ctx context.Context, userTraffic []UserTraffic) error {
	data := make(map[int][]int64, len(userTraffic))
	for i := range userTraffic {
		data[userTraffic[i].UID] = []int64{userTraffic[i].Upload, userTraffic[i].Download}
	}
	const path = "/api/v1/server/UniProxy/push"
	_, err := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) ReportNodeOnlineUsers(ctx context.Context, data *map[int][]string) error {
	const path = "/api/v1/server/UniProxy/alive"
	_, err := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)

	if err != nil {
		return err
	}

	return nil
}

// DGLease is one address a DynamicGuard node currently leases from its pool.
// UID is the panel's credential id, the same value the user list calls an id.
type DGLease struct {
	UID        int    `json:"uid"`
	DeviceID   string `json:"device_id"`
	IP         string `json:"ip"`
	LastSeenAt string `json:"last_seen_at"`
}

// ReportDGLeases sends the node's whole device table. An empty snapshot is sent
// too: it is how the node says it leases nothing any more, and skipping it would
// leave the panel showing addresses that were released.
func (c *Client) ReportDGLeases(ctx context.Context, leases []DGLease) error {
	if leases == nil {
		leases = []DGLease{}
	}
	return c.postReport(ctx, leasesPath, map[string]any{"leases": leases})
}

// AccessLogEntry is one connection this node carried. A DynamicGuard node fills
// the five-tuple; a SATLS node fills what its sniffer resolved, so Domain may be
// the only destination it knows.
type AccessLogEntry struct {
	UID      int    `json:"uid"`
	Ts       string `json:"ts"`
	Protocol string `json:"protocol"`
	IPProto  int    `json:"ip_proto,omitempty"`
	SrcIP    string `json:"src_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	Domain   string `json:"domain,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
}

// AccessLogBatchSize bounds one request. The caller chunks rather than the
// panel refusing an oversized body.
const AccessLogBatchSize = 1000

// ReportAccessLogs posts one batch.
func (c *Client) ReportAccessLogs(ctx context.Context, logs []AccessLogEntry) error {
	if len(logs) == 0 {
		return nil
	}
	return c.postReport(ctx, logsPath, map[string]any{"logs": logs})
}

const (
	leasesPath = "/api/v1/server/UniProxy/leases"
	logsPath   = "/api/v1/server/UniProxy/logs"
)

// postReport sends one additive report. These two endpoints are not part of the
// five every v2board-style panel implements, so a panel that does not know them
// answers 404 — and a DynamicGuard node would otherwise keep posting a lease
// snapshot at it on every push, forever. The first 404 latches the endpoint off
// for this client, which lives until the next reload; a panel that gains the
// endpoint is a configuration change, and that reloads the node anyway.
//
// Any other status is ignored exactly like the traffic and alive reports ignore
// theirs: these are observations, and losing one must never stall the push task
// carrying the counters that bill.
func (c *Client) postReport(ctx context.Context, path string, body any) error {
	if _, unsupported := c.unsupported.Load(path); unsupported {
		return nil
	}
	r, err := c.client.R().
		SetContext(ctx).
		SetBody(body).
		ForceContentType("application/json").
		Post(path)
	if err != nil {
		return err
	}
	if r != nil && r.StatusCode() == http.StatusNotFound {
		c.unsupported.Store(path, struct{}{})
		logrus.WithFields(logrus.Fields{"path": path, "host": c.APIHost}).
			Info("panel does not implement this report; skipping it until the next reload")
	}
	return nil
}
