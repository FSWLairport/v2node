package core

import (
	"encoding/json"
	"fmt"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// build default freedom outbund
func buildDefaultOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = "Default"
	//sendthrough := "origin"
	//outboundDetourConfig.SendThrough = &sendthrough

	proxySetting := &conf.FreedomConfig{
		DomainStrategy: "UseIPv4v6",
	}
	var setting json.RawMessage
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy config error: %s", err)
	}
	outboundDetourConfig.Settings = &setting
	return outboundDetourConfig.Build()
}

// buildEgressOutbound is one node's own freedom outbound: traffic leaves from
// sendThrough (a specific address, "" for the host's choice) and, when asked,
// carries a fwmark for policy routing. domainStrategy narrows a per-family
// outbound to its family.
func buildEgressOutbound(tag, sendThrough, domainStrategy string, fwmark uint32) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{Protocol: "freedom", Tag: tag}
	if sendThrough != "" {
		outboundDetourConfig.SendThrough = &sendThrough
	}
	if fwmark != 0 {
		outboundDetourConfig.StreamSetting = &conf.StreamConfig{SocketSettings: &conf.SocketConfig{Mark: int32(fwmark)}}
	}
	setting, err := json.Marshal(&conf.FreedomConfig{DomainStrategy: domainStrategy})
	if err != nil {
		return nil, fmt.Errorf("marshal proxy config error: %s", err)
	}
	raw := json.RawMessage(setting)
	outboundDetourConfig.Settings = &raw
	return outboundDetourConfig.Build()
}

// build block outbund
func buildBlockOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "blackhole"
	outboundDetourConfig.Tag = "block"
	return outboundDetourConfig.Build()
}

// build dns outbound
func buildDnsOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "dns"
	outboundDetourConfig.Tag = "dns_out"
	return outboundDetourConfig.Build()
}
