package node

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/task"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/core"
	"github.com/wyx2685/v2node/limiter"
	"github.com/wyx2685/v2node/proxy/dynamicguard"
)

type Controller struct {
	server                  *core.V2Core
	apiClient               *panel.Client
	tag                     string
	limiter                 *limiter.Limiter
	userList                []panel.UserInfo
	aliveMap                map[int]int
	conf                    *conf.NodeConfig
	info                    *panel.NodeInfo
	nodeInfoMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	renewCertPeriodic       *task.Task
	// DynamicGuard
	dgServer *dynamicguard.DGServer
}

// NewController return a Node controller with default parameters.
func NewController(api *panel.Client, conf *conf.NodeConfig, info *panel.NodeInfo) *Controller {
	controller := &Controller{
		apiClient: api,
		info:      info,
		conf:      conf,
	}
	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start(x *core.V2Core) error {
	// Init Core
	c.server = x
	var err error
	// First fetch Node Info
	node := c.info
	if node == nil {
		c.info, err = c.apiClient.GetNodeInfo(context.Background())
		if err != nil {
			return fmt.Errorf("get node info error: %s", err)
		}
		node = c.info
	}
	// Update user
	c.userList, err = c.apiClient.GetUserList(context.Background())
	if err != nil {
		return fmt.Errorf("get user list error: %s", err)
	}
	c.aliveMap, err = c.apiClient.GetUserAlive(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get user alive list: %s", err)
	}
	c.tag = node.Tag

	// DynamicGuard 走独立路径，不使用 xray-core
	if node.Type == "dynamicguard" {
		return c.startDynamicGuard(node)
	}

	// add limiter
	l := limiter.AddLimiter(c.info.Type, c.tag, c.userList, c.aliveMap)
	c.limiter = l
	if node.Security == panel.Tls {
		err = c.requestCert()
		if err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	// Add new tag
	err = c.server.AddNode(c.tag, node)
	if err != nil {
		return fmt.Errorf("add new node error: %s", err)
	}
	added, err := c.server.AddUsers(&core.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: node,
	})
	if err != nil {
		return fmt.Errorf("add users error: %s", err)
	}
	log.WithField("tag", c.tag).Infof("Added %d new users", added)
	c.info = node
	c.startTasks(node)
	return nil
}

func (c *Controller) startDynamicGuard(node *panel.NodeInfo) error {
	dgSettings := node.Common.DGSettings
	if dgSettings == nil {
		return fmt.Errorf("dynamicguard node missing dg_settings")
	}

	listenAddr := fmt.Sprintf("%s:%d", node.Common.ListenIP, node.Common.ServerPort)
	if node.Common.ListenIP == "" {
		listenAddr = fmt.Sprintf(":%d", node.Common.ServerPort)
	}

	log.WithFields(log.Fields{
		"tag":            c.tag,
		"listen":         listenAddr,
		"lease_ttl":      dgSettings.LeaseTTL,
		"ip_pool_count":  len(dgSettings.IPPools),
		"route_count":    len(dgSettings.Routes),
		"acl_networks":   len(dgSettings.ACL),
		"cookie_enabled": dgSettings.CookieEnabled,
		"pow_difficulty": dgSettings.PowDifficulty,
		"mtu":            dgSettings.MTU,
	}).Info("Starting DynamicGuard node")

	dgServer, err := dynamicguard.NewDGServer(&dynamicguard.DGServerConfig{
		ListenAddr: listenAddr,
		DGSettings: &dynamicguard.DGSettings{
			ServerWGKeyPath:   dgSettings.ServerWGKeyPath,
			ServerWGPublicKey: dgSettings.ServerWGPublicKey,
			LeaseTTL:          dgSettings.LeaseTTL,
			IPPools:           dgSettings.IPPools,
			Routes:            dgSettings.Routes,
			ACL:               dgSettings.ACL,
			CookieEnabled:     dgSettings.CookieEnabled,
			PowDifficulty:     dgSettings.PowDifficulty,
			MTU:               dgSettings.MTU,
		},
	})
	if err != nil {
		return fmt.Errorf("create DG server: %w", err)
	}

	// 构建用户列表
	c.updateDGUsers(dgServer)

	if err := dgServer.Start(); err != nil {
		return fmt.Errorf("start DG server: %w", err)
	}

	c.dgServer = dgServer
	log.WithFields(log.Fields{
		"tag":        c.tag,
		"user_count": len(c.userList),
	}).Info("DynamicGuard node started")
	c.startTasks(node)
	return nil
}

func (c *Controller) updateDGUsers(dgServer *dynamicguard.DGServer) {
	users := make([]*dynamicguard.UserEntry, 0, len(c.userList))
	for _, u := range c.userList {
		userKey := dynamicguard.UserKeyFromUUID(u.Uuid)
		users = append(users, &dynamicguard.UserEntry{
			UserID:      u.Id,
			UUID:        u.Uuid,
			UserKey:     userKey,
			DeviceLimit: u.DeviceLimit,
			SpeedLimit:  u.SpeedLimit,
			GroupID:     u.GroupID,
		})
	}
	dgServer.UpdateUsers(users)
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	limiter.DeleteLimiter(c.tag)
	if c.nodeInfoMonitorPeriodic != nil {
		c.nodeInfoMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
	}
	// DynamicGuard 关闭
	if c.dgServer != nil {
		c.dgServer.Close()
		return nil
	}
	err := c.server.DelNode(c.tag)
	if err != nil {
		return fmt.Errorf("del node error: %s", err)
	}
	return nil
}
