package node

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/accesslog"
)

func (c *Controller) reportUserTrafficTask(ctx context.Context) (err error) {
	// DynamicGuard 流量上报
	if c.dgServer != nil {
		return c.reportDGTraffic(ctx)
	}
	defer c.reportXrayAccessLogs(ctx)

	var reportmin = 0
	var devicemin = 0
	if c.info.Common.BaseConfig != nil {
		reportmin = c.info.Common.BaseConfig.NodeReportMinTraffic
		devicemin = c.info.Common.BaseConfig.DeviceOnlineMinTraffic
	}
	userTraffic, _ := c.server.GetUserTrafficSlice(c.tag, reportmin)
	if len(userTraffic) > 0 {
		err = c.apiClient.ReportUserTraffic(ctx, userTraffic)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report user traffic failed")
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
		} else {
			log.WithField("tag", c.tag).Infof("Report %d users traffic", len(userTraffic))
			//log.WithField("tag", c.tag).Debugf("User traffic: %+v", userTraffic)
		}
	}

	if onlineDevice, err := c.limiter.GetOnlineDevice(); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("Get online device failed")
	} else if len(*onlineDevice) > 0 {
		var result []panel.OnlineUser
		var nocountUID = make(map[int]struct{})
		for _, traffic := range userTraffic {
			total := traffic.Upload + traffic.Download
			if total < int64(devicemin*1000) {
				nocountUID[traffic.UID] = struct{}{}
			}
		}
		for _, online := range *onlineDevice {
			if _, ok := nocountUID[online.UID]; !ok {
				result = append(result, online)
			}
		}
		data := make(map[int][]string)
		for _, onlineuser := range result {
			// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
			data[onlineuser.UID] = append(data[onlineuser.UID], onlineuser.IP)
		}
		if len(data) != 0 {
			err := c.apiClient.ReportNodeOnlineUsers(ctx, &data)
			if err != nil {
				log.WithFields(log.Fields{
					"tag": c.tag,
					"err": err,
				}).Info("Report online users failed")
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
			}
		}
		log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", len(*onlineDevice), len(result))
	}

	return nil
}

func (c *Controller) reportDGTraffic(ctx context.Context) error {
	c.reportDGLeases(ctx)
	c.reportDGAccessLogs(ctx)

	dgTraffic := c.dgServer.GetUserTraffic()
	if len(dgTraffic) == 0 {
		return nil
	}

	userTraffic := make([]panel.UserTraffic, 0, len(dgTraffic))
	for _, t := range dgTraffic {
		userTraffic = append(userTraffic, panel.UserTraffic{
			UID:      t.UserID,
			Upload:   t.Upload,
			Download: t.Download,
		})
	}

	err := c.apiClient.ReportUserTraffic(ctx, userTraffic)
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("Report DG user traffic failed")
	} else {
		log.WithField("tag", c.tag).Infof("Report %d DG users traffic", len(userTraffic))
	}
	return nil
}

// reportDGLeases publishes the node's whole device table. It is not gated by the
// access-log switch: the cloud publishes each entry's pool but never picks the
// address inside it, so this is the only way it learns which client holds what.
func (c *Controller) reportDGLeases(ctx context.Context) {
	devices := c.dgServer.ActiveDevices()
	leases := make([]panel.DGLease, 0, len(devices))
	for _, entry := range devices {
		if !entry.AssignedIP.IsValid() {
			continue
		}
		leases = append(leases, panel.DGLease{
			UID:        entry.UserID,
			DeviceID:   hex.EncodeToString(entry.DeviceID[:]),
			IP:         entry.AssignedIP.String(),
			LastSeenAt: entry.LastSeen.UTC().Format(time.RFC3339),
		})
	}
	// An empty snapshot is sent too: it is how the node says it released
	// everything, and skipping it would leave stale addresses on the panel.
	if err := c.apiClient.ReportDGLeases(ctx, leases); err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("Report DG leases failed")
		return
	}
	log.WithField("tag", c.tag).Debugf("Reported %d DG leases", len(leases))
}

func (c *Controller) reportDGAccessLogs(ctx context.Context) {
	if !c.accessLogEnabled() {
		return
	}
	records := c.dgServer.DrainFlowRecords()
	entries := make([]panel.AccessLogEntry, 0, len(records))
	for _, record := range records {
		entries = append(entries, panel.AccessLogEntry{
			UID:       record.UserID,
			Ts:        record.At.UTC().Format(time.RFC3339),
			Protocol:  "dg",
			Transport: record.Transport(),
			SrcIP:     record.Src.String(),
			SrcPort:   int(record.SrcPort),
			DstIP:     record.Dst.String(),
			DstPort:   int(record.DstPort),
			DeviceID:  hex.EncodeToString(record.DeviceID[:]),
		})
	}
	c.postAccessLogs(ctx, entries)
}

func (c *Controller) reportXrayAccessLogs(ctx context.Context) {
	if !c.accessLogEnabled() {
		return
	}
	records := accesslog.Drain(c.tag)
	entries := make([]panel.AccessLogEntry, 0, len(records))
	for _, record := range records {
		uid := c.server.UIDByEmail(record.Email)
		if uid == 0 {
			// The credential went away between the connection and this drain;
			// the panel would reject the record anyway.
			continue
		}
		if record.DstIP == "" && record.Domain == "" {
			continue
		}
		entries = append(entries, panel.AccessLogEntry{
			UID:       uid,
			Ts:        record.At.UTC().Format(time.RFC3339),
			Protocol:  "satls",
			Transport: record.Transport,
			SrcIP:     record.SrcIP,
			SrcPort:   record.SrcPort,
			DstIP:     record.DstIP,
			DstPort:   record.DstPort,
			Domain:    record.Domain,
		})
	}
	c.postAccessLogs(ctx, entries)
}

// postAccessLogs sends in batches and never fails the report task: these are
// observations, and losing a batch must not cost the traffic push behind it.
func (c *Controller) postAccessLogs(ctx context.Context, entries []panel.AccessLogEntry) {
	for start := 0; start < len(entries); start += panel.AccessLogBatchSize {
		end := min(start+panel.AccessLogBatchSize, len(entries))
		if err := c.apiClient.ReportAccessLogs(ctx, entries[start:end]); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("Report access logs failed")
			return
		}
	}
	if len(entries) > 0 {
		log.WithField("tag", c.tag).Debugf("Reported %d access records", len(entries))
	}
}

func compareUserList(old, new []panel.UserInfo) (deleted, added, modified []panel.UserInfo) {
	oldMap := make(map[string]panel.UserInfo, len(old))
	for _, u := range old {
		oldMap[u.Uuid] = u
	}

	for _, u := range new {
		if o, ok := oldMap[u.Uuid]; !ok {
			added = append(added, u)
		} else {
			if o.SpeedLimit != u.SpeedLimit || o.DeviceLimit != u.DeviceLimit {
				modified = append(modified, u)
			}
			delete(oldMap, u.Uuid)
		}
	}

	for _, o := range oldMap {
		deleted = append(deleted, o)
	}

	return deleted, added, modified
}
