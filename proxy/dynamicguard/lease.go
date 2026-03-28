package dynamicguard

import (
	"time"

	log "github.com/sirupsen/logrus"
)

// LeaseManager 租约管理器
type LeaseManager struct {
	deviceTable *DeviceTable
	wgDevice    *WGDevice
	ipPools     map[int]*IPPool
	leaseTTL    time.Duration
	stopCh      chan struct{}
}

// NewLeaseManager 创建租约管理器
func NewLeaseManager(dt *DeviceTable, wg *WGDevice, pools map[int]*IPPool, leaseTTL time.Duration) *LeaseManager {
	return &LeaseManager{
		deviceTable: dt,
		wgDevice:    wg,
		ipPools:     pools,
		leaseTTL:    leaseTTL,
		stopCh:      make(chan struct{}),
	}
}

// Start 启动租约清理 goroutine
func (lm *LeaseManager) Start() {
	go lm.cleanupLoop()
	log.Infof("[DynamicGuard] lease manager started, TTL=%s", lm.leaseTTL)
}

// Close 停止租约管理器
func (lm *LeaseManager) Close() {
	close(lm.stopCh)
}

func (lm *LeaseManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lm.doCleanup()
		case <-lm.stopCh:
			return
		}
	}
}

func (lm *LeaseManager) doCleanup() {
	expired := lm.deviceTable.CleanExpired(lm.leaseTTL)
	if len(expired) == 0 {
		return
	}

	for _, ed := range expired {
		log.WithFields(log.Fields{
			"user_id":  ed.Entry.UserID,
			"group_id": ed.Entry.GroupID,
			"ip":       ed.OldIP.String(),
		}).Debug("[DynamicGuard] cleaning expired device")
		// 从 WireGuard 移除 peer
		if err := lm.wgDevice.RemovePeer(ed.Entry.WGStaticPub); err != nil {
			log.Warnf("[DynamicGuard] remove expired peer failed: %v", err)
		}

		// 用旧 IP 释放地址池
		if pool, ok := lm.ipPools[ed.Entry.GroupID]; ok {
			pool.Release(ed.OldIP)
		}

		log.Debugf("[DynamicGuard] expired device user=%d ip=%s", ed.Entry.UserID, ed.OldIP)
	}

	log.Infof("[DynamicGuard] cleaned %d expired devices", len(expired))
}
