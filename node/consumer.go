package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/consumertraffic"
	"github.com/wyx2685/v2node/common/format"
	"github.com/wyx2685/v2node/common/grantlimit"
	"github.com/wyx2685/v2node/common/userlease"
	vCore "github.com/wyx2685/v2node/core"
)

func (c *Controller) consumerPath() string {
	if c.conf.ConsumerTrafficFile != "" {
		return c.conf.ConsumerTrafficFile
	}
	scope := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", c.conf.APIHost, c.conf.NodeID)))
	return filepath.Join("/var/lib/v2node/consumer-traffic", hex.EncodeToString(scope[:12])+".json")
}
func (c *Controller) ensureConsumerStoreLocked() error {
	if c.consumerStore != nil {
		return nil
	}
	store, err := consumertraffic.Open(c.consumerPath())
	if err != nil {
		return err
	}
	c.consumerStore = store
	return nil
}
func (c *Controller) initializeConsumers() {
	c.usersMu.Lock()
	defer c.usersMu.Unlock()
	c.billingUsers = map[int]panel.UserInfo{}
	c.legacyTraffic = map[int][2]int64{}
	c.teardown = map[int]panel.UserInfo{}
	for _, u := range c.userList {
		if u.ConsumerLeaseID != "" {
			c.consumerRequested = true
		}
	}
	if _, err := os.Stat(c.consumerPath()); err == nil {
		c.consumerRequested = true
	}
	incoming := c.userList
	c.userList = nil
	c.userList = c.filterConsumerUsersLocked(incoming, true)
	c.installConsumerLeasesLocked(c.userList)
}
func (c *Controller) filterConsumerUsersLocked(users []panel.UserInfo, renew bool) []panel.UserInfo {
	for _, u := range users {
		if u.ConsumerLeaseID != "" {
			c.consumerRequested = true
		}
	}
	if c.consumerRequested && c.consumerStore == nil {
		if err := c.ensureConsumerStoreLocked(); err != nil {
			log.WithField("tag", c.tag).WithError(err).Error("Consumer accounting unavailable; C credentials remain disabled")
			renew = false
		} else if !c.consumerStore.CanRenew() {
			renew = false
		}
	}
	if c.consumerStore == nil {
		renew = false
	}
	previous := map[int]panel.UserInfo{}
	for _, u := range c.userList {
		previous[u.Id] = u
	}
	filtered := make([]panel.UserInfo, 0, len(users))
	for _, u := range users {
		if _, pending := c.teardown[u.Id]; pending {
			continue
		}
		if u.ConsumerLeaseID != "" {
			if !time.Now().Before(u.LeaseDeadline) {
				continue
			}
			if !renew {
				old, exists := previous[u.Id]
				if !exists || old.ConsumerLeaseID != u.ConsumerLeaseID || old.EntitlementGeneration != u.EntitlementGeneration || !time.Now().Before(old.LeaseDeadline) {
					continue
				}
				u = old
			}
		}
		filtered = append(filtered, u)
	}
	return filtered
}
func (c *Controller) installConsumerLeasesLocked(users []panel.UserInfo) {
	grants := make(map[string][]grantlimit.Limit, len(users))
	for _, u := range users {
		grants[format.UserTag(c.tag, u.Uuid)] = u.GrantBandwidthLimits
	}
	grantlimit.Configure(c.tag, grants)
	for _, u := range users {
		if u.ConsumerLeaseID == "" {
			continue
		}
		key := format.UserTag(c.tag, u.Uuid)
		userlease.ConfigureRate(key, fmt.Sprintf("%s:account:%d", c.tag, u.ConsumerAccountID), u.SpeedLimit)
		var closeConnections func()
		if c.info.Type != "dynamicguard" {
			uuid := u.Uuid
			closeConnections = func() { c.server.CloseUserConnections(c.tag, uuid) }
		}
		userlease.Set(key, u.LeaseDeadline, closeConnections)
		c.billingUsers[u.Id] = u
	}
}
func (c *Controller) revokeConsumerLocked(u panel.UserInfo) {
	if u.ConsumerLeaseID != "" {
		userlease.Revoke(format.UserTag(c.tag, u.Uuid))
	}
}

// Caller holds usersMu. No HTTP operation may run while it is held.
func (c *Controller) snapshotTrafficLocked(consumerOnly bool) error {
	room := c.consumerStore == nil || c.consumerStore.Room(2*len(c.billingUsers))
	if !room && consumerOnly {
		return fmt.Errorf("consumer accounting queue cannot accept another snapshot")
	}
	var traffic []panel.UserTraffic
	if c.dgServer != nil {
		if consumerOnly {
			for _, v := range c.dgServer.GetConsumerTraffic() {
				traffic = append(traffic, panel.UserTraffic{UID: v.UserID, Upload: v.Upload, Download: v.Download})
			}
		} else {
			raw := c.dgServer.GetUserTraffic
			if !room {
				raw = c.dgServer.GetEnterpriseTraffic
			}
			for _, v := range raw() {
				traffic = append(traffic, panel.UserTraffic{UID: v.UserID, Upload: v.Upload, Download: v.Download})
			}
		}
	} else {
		var err error
		if consumerOnly {
			traffic, err = c.server.GetConsumerTrafficSlice(c.tag)
		} else if !room {
			traffic, err = c.server.GetEnterpriseTrafficSlice(c.tag)
		} else {
			traffic, err = c.server.GetUserTrafficSlice(c.tag, 0)
		}
		if err != nil {
			return err
		}
	}
	type sampleKey struct {
		lease    string
		observed time.Time
	}
	samples := map[sampleKey]panel.ConsumerTrafficSample{}
	now := c.apiClient.ObservationTime().Truncate(time.Second)
	for _, v := range traffic {
		if v.Upload <= 0 && v.Download <= 0 {
			continue
		}
		user, managed := c.billingUsers[v.UID]
		if !managed {
			previous := c.legacyTraffic[v.UID]
			previous[0] += v.Upload
			previous[1] += v.Download
			c.legacyTraffic[v.UID] = previous
			continue
		}
		observed := now
		if !user.LeaseNotAfter.IsZero() && observed.After(user.LeaseNotAfter) {
			observed = user.LeaseNotAfter.Truncate(time.Second)
		}
		key := sampleKey{user.ConsumerLeaseID, observed}
		sample := samples[key]
		sample.LeaseID = key.lease
		sample.Upload += v.Upload
		sample.Download += v.Download
		samples[key] = sample
	}
	if len(samples) == 0 {
		if !room {
			return fmt.Errorf("consumer accounting queue cannot accept another snapshot")
		}
		return nil
	}
	if c.consumerStore == nil {
		return fmt.Errorf("consumer accounting store missing")
	}
	grouped := map[time.Time][]panel.ConsumerTrafficSample{}
	for key, sample := range samples {
		grouped[key.observed] = append(grouped[key.observed], sample)
	}
	batches := []panel.ConsumerTrafficBatch{}
	for observed, group := range grouped {
		slices.SortFunc(group, func(a, b panel.ConsumerTrafficSample) int {
			if a.LeaseID < b.LeaseID {
				return -1
			}
			if a.LeaseID == b.LeaseID {
				return 0
			}
			return 1
		})
		for len(group) > 0 {
			size := min(len(group), 500)
			batches = append(batches, panel.ConsumerTrafficBatch{ID: uuid.NewString(), ObservedAt: observed, Samples: slices.Clone(group[:size])})
			group = group[size:]
		}
	}
	return c.consumerStore.Add(batches)
}

func (c *Controller) flushConsumerTraffic(ctx context.Context) error {
	c.consumerFlushMu.Lock()
	defer c.consumerFlushMu.Unlock()
	c.usersMu.Lock()
	store := c.consumerStore
	c.usersMu.Unlock()
	if store == nil {
		return nil
	}
	if err := store.RetrySave(); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		batch, ok := store.First()
		if !ok {
			return nil
		}
		if err := c.apiClient.ReportConsumerTraffic(ctx, batch); err != nil {
			return err
		}
		if err := store.Ack(batch.ID); err != nil {
			return err
		}
	}
}

func (c *Controller) drainLegacyTrafficLocked(minimum int) []panel.UserTraffic {
	out := []panel.UserTraffic{}
	for id, raw := range c.legacyTraffic {
		if raw[0]+raw[1] > int64(minimum)*1000 {
			out = append(out, panel.UserTraffic{UID: id, Upload: raw[0], Download: raw[1]})
			delete(c.legacyTraffic, id)
		}
	}
	return out
}

func (c *Controller) applyUsersLocked(incoming []panel.UserInfo) error {
	if incoming == nil || c.closed {
		return nil
	}
	renew := c.consumerStore == nil || c.consumerStore.CanRenew()
	if err := c.snapshotTrafficLocked(false); err != nil {
		renew = false
		for _, u := range c.userList {
			c.revokeConsumerLocked(u)
		}
	}
	incoming = c.filterConsumerUsersLocked(incoming, renew)
	deleted, added, modified := compareUserList(c.userList, incoming)
	for _, u := range deleted {
		c.revokeConsumerLocked(u)
		var err error
		if c.dgServer != nil {
			err = c.dgServer.RemoveUser(u.Id)
		} else {
			err = c.server.DelUsers([]panel.UserInfo{u}, c.tag, c.info)
		}
		if err != nil {
			c.teardown[u.Id] = u
		}
	}
	if err := c.snapshotTrafficLocked(false); err != nil {
		for _, u := range c.userList {
			c.revokeConsumerLocked(u)
		}
		return err
	}
	next := incoming[:0]
	for _, u := range incoming {
		if _, pending := c.teardown[u.Id]; !pending {
			next = append(next, u)
		}
	}
	incoming = next
	c.installConsumerLeasesLocked(incoming)
	successful := []panel.UserInfo{}
	for _, u := range added {
		if _, pending := c.teardown[u.Id]; pending {
			continue
		}
		if c.dgServer == nil {
			if _, err := c.server.AddUsers(&vCore.AddUsersParams{Tag: c.tag, NodeInfo: c.info, Users: []panel.UserInfo{u}}); err != nil {
				c.revokeConsumerLocked(u)
				c.teardown[u.Id] = u
				continue
			}
		}
		successful = append(successful, u)
	}
	c.userList = incoming
	if len(c.teardown) > 0 {
		filtered := c.userList[:0]
		for _, u := range c.userList {
			if _, pending := c.teardown[u.Id]; !pending {
				filtered = append(filtered, u)
			}
		}
		c.userList = filtered
	}
	for _, u := range deleted {
		if _, pending := c.teardown[u.Id]; !pending {
			delete(c.billingUsers, u.Id)
		}
	}
	// Replaced credentials retain the fresh generation's attribution.
	for _, u := range c.userList {
		if u.ConsumerLeaseID != "" {
			c.billingUsers[u.Id] = u
		}
	}
	if c.dgServer != nil {
		c.updateDGUsers(c.dgServer)
	} else if c.limiter != nil {
		c.limiter.UpdateUser(c.tag, successful, deleted, modified)
	}
	return nil
}

func (c *Controller) expireConsumers() {
	c.usersMu.Lock()
	defer c.usersMu.Unlock()
	expired := map[int]bool{}
	for _, u := range c.userList {
		if u.ConsumerLeaseID != "" && (!time.Now().Before(u.LeaseDeadline) || !userlease.Allowed(format.UserTag(c.tag, u.Uuid))) {
			c.revokeConsumerLocked(u)
			c.teardown[u.Id] = u
			expired[u.Id] = true
		}
	}
	if len(c.teardown) == 0 {
		return
	}
	if err := c.snapshotTrafficLocked(true); err != nil {
		log.WithField("tag", c.tag).WithError(err).Error("Preserve consumer traffic before teardown")
	}
	for id, u := range c.teardown {
		var err error
		if c.dgServer != nil {
			err = c.dgServer.RemoveUser(id)
		} else {
			err = c.server.DelUsers([]panel.UserInfo{u}, c.tag, c.info)
		}
		if err != nil {
			continue
		}
		if err = c.snapshotTrafficLocked(true); err != nil {
			continue
		}
		delete(c.teardown, id)
		delete(c.billingUsers, id)
	}
	filtered := c.userList[:0]
	removed := []panel.UserInfo{}
	for _, u := range c.userList {
		if expired[u.Id] {
			removed = append(removed, u)
		} else {
			filtered = append(filtered, u)
		}
	}
	c.userList = filtered
	if c.dgServer != nil {
		c.updateDGUsers(c.dgServer)
	} else if c.limiter != nil && len(removed) > 0 {
		c.limiter.UpdateUser(c.tag, nil, removed, nil)
	}
}
func (c *Controller) maintainConsumers(ctx context.Context) error {
	c.usersMu.Lock()
	if !c.consumerRequested && c.consumerStore == nil {
		c.usersMu.Unlock()
		return nil
	}
	if err := c.ensureConsumerStoreLocked(); err != nil {
		c.usersMu.Unlock()
		return err
	}
	err := c.snapshotTrafficLocked(true)
	if err != nil {
		for _, u := range c.userList {
			c.revokeConsumerLocked(u)
		}
	}
	c.usersMu.Unlock()
	if err != nil {
		return err
	}
	if err = c.flushConsumerTraffic(ctx); err != nil {
		return err
	}
	c.usersMu.Lock()
	pull := time.Since(c.lastConsumerPull) >= 15*time.Second || len(c.billingUsers) == 0
	c.usersMu.Unlock()
	if !pull {
		return nil
	}
	users, err := c.apiClient.GetUserList(ctx)
	if err != nil {
		return err
	}
	c.usersMu.Lock()
	defer c.usersMu.Unlock()
	c.lastConsumerPull = time.Now()
	return c.applyUsersLocked(users)
}
func (c *Controller) startConsumerTasks() {
	ctx, cancel := context.WithCancel(context.Background())
	c.consumerCancel = cancel
	c.consumerWorkers.Add(2)
	go func() {
		defer c.consumerWorkers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.expireConsumers()
			}
		}
	}()
	go func() {
		defer c.consumerWorkers.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				work, stop := context.WithTimeout(ctx, 4*time.Second)
				err := c.maintainConsumers(work)
				stop()
				if err != nil && ctx.Err() == nil {
					log.WithField("tag", c.tag).WithError(err).Warn("Consumer accounting/lease refresh incomplete")
				}
			}
		}
	}()
}
