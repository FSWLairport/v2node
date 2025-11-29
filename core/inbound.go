package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/proxy/satls"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func (v *V2Core) removeInbound(tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return v.ihm.RemoveHandler(ctx, tag)
}

func (v *V2Core) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(v.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := v.ihm.AddHandler(ctx, handler); err != nil {
		return err
	}
	return nil
}

// BuildInbound build Inbound config for different protocol
func buildInbound(nodeInfo *panel.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	in := &coreConf.InboundDetourConfig{}
	var err error
	isSatls := false
	switch nodeInfo.Type {
	case "vless":
		err = buildVLess(nodeInfo, in)
	case "vmess":
		err = buildVMess(nodeInfo, in)
	case "trojan":
		err = buildTrojan(nodeInfo, in)
	case "shadowsocks":
		err = buildShadowsocks(nodeInfo, in)
	case "hysteria2":
		err = buildHysteria2(nodeInfo, in)
	case "tuic":
		err = buildTuic(nodeInfo, in)
	case "anytls":
		err = buildAnyTLS(nodeInfo, in)
	case "satls":
		err = buildSATLS(nodeInfo, in)
		isSatls = true
	default:
		return nil, fmt.Errorf("unsupported node type: %s", nodeInfo.Type)
	}
	if err != nil {
		return nil, err
	}
	// Set network protocol
	// Set server port
	in.PortList = &coreConf.PortList{
		Range: []coreConf.PortRange{
			{
				From: uint32(nodeInfo.Common.ServerPort),
				To:   uint32(nodeInfo.Common.ServerPort),
			}},
	}
	// Set Listen IP address
	ipAddress := net.ParseAddress(nodeInfo.Common.ListenIP)
	in.ListenOn = &coreConf.Address{Address: ipAddress}
	// Set SniffingConfig
	sniffingConfig := &coreConf.SniffingConfig{
		Enabled:      true,
		DestOverride: &coreConf.StringList{"http", "tls"},
	}
	in.SniffingConfig = sniffingConfig

	// Set TLS or Reality settings
	switch nodeInfo.Security {
	case panel.Tls:
		if nodeInfo.Common.CertInfo == nil {
			return nil, errors.New("the CertInfo is not vail")
		}
		switch nodeInfo.Common.CertInfo.CertMode {
		case "none", "":
			break
		default:
			if in.StreamSetting == nil {
				in.StreamSetting = &coreConf.StreamConfig{}
			}
			in.StreamSetting.Security = "tls"
			in.StreamSetting.TLSSettings = &coreConf.TLSConfig{
				Certs: []*coreConf.TLSCertConfig{
					{
						CertFile:     nodeInfo.Common.CertInfo.CertFile,
						KeyFile:      nodeInfo.Common.CertInfo.KeyFile,
						OcspStapling: 3600,
					},
				},
				RejectUnknownSNI: nodeInfo.Common.CertInfo.RejectUnknownSni,
			}
		}
	case panel.Reality:
		if in.StreamSetting == nil {
			in.StreamSetting = &coreConf.StreamConfig{}
		}
		in.StreamSetting.Security = "reality"
		v := nodeInfo.Common
		dest := v.TlsSettings.Dest
		if dest == "" {
			dest = v.TlsSettings.ServerName
		}
		xver := v.TlsSettings.Xver
		d, err := json.Marshal(fmt.Sprintf(
			"%s:%s",
			dest,
			v.TlsSettings.ServerPort))
		if err != nil {
			return nil, fmt.Errorf("marshal reality dest error: %s", err)
		}
		in.StreamSetting.REALITYSettings = &coreConf.REALITYConfig{
			Dest:        d,
			Xver:        xver,
			Show:        false,
			ServerNames: []string{v.TlsSettings.ServerName},
			PrivateKey:  v.TlsSettings.PrivateKey,
			ShortIds:    []string{v.TlsSettings.ShortId},
			Mldsa65Seed: v.TlsSettings.Mldsa65Seed,
		}
	default:
		break
	}
	in.Tag = tag
	if isSatls {
		return buildSATLSInbound(nodeInfo, in)
	}
	return in.Build()
}

func buildVLess(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	v := nodeInfo.Common
	inbound.Protocol = "vless"
	var err error
	decryption := "none"
	if nodeInfo.Common.Encryption != "" {
		switch nodeInfo.Common.Encryption {
		case "mlkem768x25519plus":
			encSettings := nodeInfo.Common.EncryptionSettings
			parts := []string{
				"mlkem768x25519plus",
				encSettings.Mode,
				encSettings.Ticket,
			}
			if encSettings.ServerPadding != "" {
				parts = append(parts, encSettings.ServerPadding)
			}
			parts = append(parts, encSettings.PrivateKey)
			decryption = strings.Join(parts, ".")
		default:
			return fmt.Errorf("vless decryption method %s is not support", nodeInfo.Common.Encryption)
		}
	}
	s, err := json.Marshal(&coreConf.VLessInboundConfig{
		Decryption: decryption,
	})
	if err != nil {
		return fmt.Errorf("marshal vless config error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	if len(v.NetworkSettings) == 0 {
		return nil
	}
	t := coreConf.TransportProtocol(v.Network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch v.Network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	case "httpupgrade":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings)
		if err != nil {
			return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
		}
	case "splithttp", "xhttp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal xhttp settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildVMess(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	v := nodeInfo.Common
	// Set vmess
	inbound.Protocol = "vmess"
	var err error
	s, err := json.Marshal(&coreConf.VMessInboundConfig{})
	if err != nil {
		return fmt.Errorf("marshal vmess settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	if len(v.NetworkSettings) == 0 {
		return nil
	}
	t := coreConf.TransportProtocol(v.Network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch v.Network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	case "httpupgrade":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings)
		if err != nil {
			return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
		}
	case "splithttp", "xhttp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal xhttp settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildTrojan(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "trojan"
	v := nodeInfo.Common
	s, err := json.Marshal(&coreConf.TrojanServerConfig{})
	if err != nil {
		return fmt.Errorf("marshal trojan settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	network := v.Network
	if network == "" {
		network = "tcp"
	}
	t := coreConf.TransportProtocol(network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	if len(v.NetworkSettings) == 0 {
		return nil
	}
	switch network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

type ShadowsocksHTTPNetworkSettings struct {
	AcceptProxyProtocol bool   `json:"acceptProxyProtocol"`
	Path                string `json:"path"`
	Host                string `json:"Host"`
}

func buildShadowsocks(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "shadowsocks"
	s := nodeInfo.Common
	settings := &coreConf.ShadowsocksServerConfig{
		Cipher: s.Cipher,
	}
	p := make([]byte, 32)
	_, err := rand.Read(p)
	if err != nil {
		return fmt.Errorf("generate random password error: %s", err)
	}
	randomPasswd := hex.EncodeToString(p)
	cipher := s.Cipher
	if s.ServerKey != "" {
		settings.Password = s.ServerKey
		randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		cipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   cipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)
	// Default: support both tcp and udp
	settings.NetworkList = &coreConf.NetworkList{"tcp", "udp"}
	settings.IVCheck = true
	// Only set StreamSetting when NetworkSettings is configured
	if len(s.NetworkSettings) != 0 {
		shttp := &ShadowsocksHTTPNetworkSettings{}
		err := json.Unmarshal(s.NetworkSettings, shttp)
		if err != nil {
			return fmt.Errorf("unmarshal shadowsocks settings error: %s", err)
		}
		// HTTP obfuscation requires TCP only (PROXY protocol can work with UDP)
		if shttp.Path != "" || shttp.Host != "" {
			// Restrict protocol-level network list to TCP only for HTTP obfuscation
			settings.NetworkList = &coreConf.NetworkList{"tcp"}
		}

		// Set StreamSetting for TCP features (PROXY protocol and/or HTTP obfuscation)
		if shttp.AcceptProxyProtocol || shttp.Path != "" || shttp.Host != "" {
			t := coreConf.TransportProtocol("tcp")
			inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
			inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
			inbound.StreamSetting.TCPSettings.AcceptProxyProtocol = shttp.AcceptProxyProtocol
			// Set HTTP header settings if path or host is configured
			if shttp.Path != "" || shttp.Host != "" {
				httpHeader := map[string]interface{}{
					"type":    "http",
					"request": map[string]interface{}{},
				}
				request := httpHeader["request"].(map[string]interface{})
				// Use "/" as default path if not specified
				path := shttp.Path
				if path == "" {
					path = "/"
				}
				request["path"] = []string{path}
				if shttp.Host != "" {
					request["headers"] = map[string]interface{}{
						"Host": []string{shttp.Host},
					}
				}
				headerJSON, err := json.Marshal(httpHeader)
				if err == nil {
					inbound.StreamSetting.TCPSettings.HeaderConfig = json.RawMessage(headerJSON)
				}
			}
		}
	}

	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal shadowsocks settings error: %s", err)
	}
	return nil
}

func buildHysteria2(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "hysteria2"
	s := nodeInfo.Common
	settings := &coreConf.Hysteria2ServerConfig{
		UpMbps:                uint64(s.UpMbps),
		DownMbps:              uint64(s.DownMbps),
		IgnoreClientBandwidth: s.Ignore_Client_Bandwidth,
		Obfs: &coreConf.Hysteria2ObfsConfig{
			Type:     s.Obfs,
			Password: s.ObfsPassword,
		},
	}

	t := coreConf.TransportProtocol("hysteria2")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}

	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal hysteria2 settings error: %s", err)
	}
	return nil
}

func buildTuic(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "tuic"
	s := nodeInfo.Common
	settings := &coreConf.TuicServerConfig{
		CongestionControl: s.CongestionControl,
		ZeroRttHandshake:  s.ZeroRTTHandshake,
	}
	t := coreConf.TransportProtocol("tuic")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal tuic settings error: %s", err)
	}
	return nil
}

func buildAnyTLS(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "anytls"
	s := nodeInfo.Common
	settings := &coreConf.AnyTLSServerConfig{
		PaddingScheme: s.PaddingScheme,
	}
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal anytls settings error: %s", err)
	}
	return nil
}

func buildSATLS(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "satls"
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	empty := json.RawMessage([]byte("{}"))
	inbound.Settings = (*json.RawMessage)(&empty)
	return nil
}

func buildSATLSInbound(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) (*core.InboundHandlerConfig, error) {
	receiverSettings := &proxyman.ReceiverConfig{}
	if inbound.ListenOn == nil {
		if inbound.PortList == nil {
			return nil, fmt.Errorf("satls: missing port")
		}
		receiverSettings.PortList = inbound.PortList.Build()
	} else {
		receiverSettings.Listen = inbound.ListenOn.Build()
		listenDS := inbound.ListenOn.Family().IsDomain() && (filepath.IsAbs(inbound.ListenOn.Domain()) || inbound.ListenOn.Domain()[0] == '@')
		listenIP := inbound.ListenOn.Family().IsIP() || (inbound.ListenOn.Family().IsDomain() && inbound.ListenOn.Domain() == "localhost")
		if listenIP {
			if inbound.PortList == nil {
				return nil, fmt.Errorf("satls: missing port for listen IP")
			}
			receiverSettings.PortList = inbound.PortList.Build()
		} else if listenDS {
			if inbound.PortList != nil {
				receiverSettings.PortList = nil
			}
		} else {
			return nil, fmt.Errorf("satls: unable to listen on domain %s", inbound.ListenOn.Domain())
		}
	}
	if inbound.StreamSetting != nil {
		ss, err := inbound.StreamSetting.Build()
		if err != nil {
			return nil, err
		}
		receiverSettings.StreamSettings = ss
	}
	if inbound.SniffingConfig != nil {
		s, err := inbound.SniffingConfig.Build()
		if err != nil {
			return nil, err
		}
		receiverSettings.SniffingSettings = s
	}
	// SATLS-specific TLS/SNI selection
	certInfo := nodeInfo.Common.CertInfo
	if certInfo == nil {
		return nil, fmt.Errorf("satls: missing cert info")
	}
	serverName := nodeInfo.Common.TlsSettings.ServerName
	upServerName := serverName
	downServerName := serverName
	rejectUnknown := certInfo.RejectUnknownSni
	if st := nodeInfo.Common.SatlsSettings; st != nil {
		allowInsecure := parseBoolLoose(st.AllowInsecure)
		if st.Host != "" {
			serverName = st.Host
		}
		if st.Split != nil {
			if st.Split.Up != nil {
				if st.Split.Up.TLS.ServerName != "" {
					upServerName = st.Split.Up.TLS.ServerName
				} else if st.Split.Up.Host != "" {
					upServerName = st.Split.Up.Host
				}
			}
			if st.Split.Down != nil {
				if st.Split.Down.TLS.ServerName != "" {
					downServerName = st.Split.Down.TLS.ServerName
				} else if st.Split.Down.Host != "" {
					downServerName = st.Split.Down.Host
				}
			}
		}
		if allowInsecure {
			rejectUnknown = false
		}
	}
	return &core.InboundHandlerConfig{
		Tag:              inbound.Tag,
		ReceiverSettings: serial.ToTypedMessage(receiverSettings),
		ProxySettings: serial.ToTypedMessage(&satls.ServerConfig{
			CertFile:         certInfo.CertFile,
			KeyFile:          certInfo.KeyFile,
			ServerName:       serverName,
			UpServerName:     upServerName,
			DownServerName:   downServerName,
			RejectUnknownSni: rejectUnknown,
		}),
	}, nil
}

func parseBoolLoose(v interface{}) bool {
	switch val := v.(type) {
	case nil:
		return false
	case bool:
		return val
	case string:
		lower := strings.ToLower(strings.TrimSpace(val))
		return lower == "true" || lower == "1" || lower == "yes" || lower == "on"
	case int:
		return val != 0
	case int64:
		return val != 0
	case float64:
		return val != 0
	default:
		// try strconv on fmt
		if s, ok := val.(fmt.Stringer); ok {
			return parseBoolLoose(s.String())
		}
		return false
	}
}
