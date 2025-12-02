package satls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	stderrs "errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/smux"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Server struct {
	policyManager  policy.Manager
	store          atomic.Value
	tlsConfig      *tls.Config
	serverName     string
	upServerName   string
	downServerName string
	upCertFile     string
	upKeyFile      string
	downCertFile   string
	downKeyFile    string
	rejectUnknown  bool

	wmu            sync.Mutex
	pendingAdds    map[string]*protocol.MemoryUser
	pendingRemoves map[string]struct{}
	pendingMu      sync.Mutex
	updateCh       chan struct{}
	stopCh         chan struct{}
	debounce       time.Duration

	sessionsMu     sync.Mutex
	splitSessions  map[string]*splitSession
	replay         *sessionIDCache
	fallbackClient *http.Client
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	coreInstance := core.MustFromContext(ctx)
	pm := coreInstance.GetFeature(policy.ManagerType()).(policy.Manager)
	s := &Server{
		policyManager:  pm,
		pendingAdds:    make(map[string]*protocol.MemoryUser),
		pendingRemoves: make(map[string]struct{}),
		updateCh:       make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
		debounce:       200 * time.Millisecond,
		splitSessions:  make(map[string]*splitSession),
		replay:         newSessionIDCache(),
	}
	s.fallbackClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSHandshakeTimeout: 5 * time.Second,
			ForceAttemptHTTP2:   true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				MaxVersion: tls.VersionTLS13,
				NextProtos: []string{"h2", "http/1.1"},
			},
		},
	}
	users := make(map[[32]byte]*protocol.MemoryUser)
	emails := make(map[string][32]byte)
	for _, raw := range config.Users {
		mu, err := raw.ToMemoryUser()
		if err != nil {
			return nil, xerrors.New("satls: bad user").Base(err)
		}
		acc, ok := mu.Account.(*MemoryAccount)
		if !ok {
			return nil, xerrors.New("satls: invalid account type")
		}
		token := normalizePathToken(acc.Path)
		if token == "" {
			return nil, stderrs.New("satls: empty path token")
		}
		sum := hashPath(token)
		users[sum] = mu
		emails[mu.Email] = sum
		acc.Path = token
	}
	s.store.Store(&userStoreSnapshot{users: users, emailIndex: emails})
	if config.CertFile == "" || config.KeyFile == "" || !fileExists(config.CertFile) || !fileExists(config.KeyFile) {
		if config.CertFile == "" || config.KeyFile == "" {
			return nil, stderrs.New("satls: missing certificate path")
		}
		if err := generateSelfSigned(s.serverName, config.CertFile, config.KeyFile); err != nil {
			return nil, err
		}
	}
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	s.tlsConfig = tlsConf
	s.serverName = strings.ToLower(strings.TrimSpace(config.ServerName))
	s.upServerName = strings.ToLower(strings.TrimSpace(config.UpServerName))
	s.downServerName = strings.ToLower(strings.TrimSpace(config.DownServerName))
	s.upCertFile = config.UpCertFile
	s.upKeyFile = config.UpKeyFile
	s.downCertFile = config.DownCertFile
	s.downKeyFile = config.DownKeyFile
	s.rejectUnknown = config.RejectUnknownSni
	go s.userUpdaterLoop()
	return s, nil
}

func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessPolicy := s.policyManager.ForLevel(0)
	_ = conn.SetReadDeadline(time.Now().Add(sessPolicy.Timeouts.Handshake))
	tlsConn, sni, err := s.acceptTLS(conn)
	if err != nil {
		s.sleepFallbackDelay()
		return err
	}
	fallbackTarget := s.fallbackHost(nil)
	remoteAddr := conn.RemoteAddr()
	conn = tlsConn
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  fmt.Sprintf("satls fallback: http read request failed: %v remote=%v target=%s", err, remoteAddr, fallbackTarget),
		})
		s.handleFallback(ctx, conn, nil, nil, fallbackTarget, sni)
		return err
	}
	fallbackTarget = s.pickFallbackTarget(req, sni)
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		s.sleepFallbackDelay()
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  fmt.Sprintf("satls fallback: read body failed: %v remote=%v target=%s", err, remoteAddr, fallbackTarget),
		})
		s.handleFallback(ctx, conn, req, nil, fallbackTarget, sni)
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	info, err := s.validateRequest(req, len(body), sni)
	if err != nil {
		if errors.Is(err, errVersionMismatch) {
			_ = writeSwitchingProtocols(conn, "VersionMismatch")
			s.writeErrorResponse(conn, http.StatusUpgradeRequired, "VersionMismatch")
		} else {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Info,
				Content:  fmt.Sprintf("satls fallback: validation failed: %v remote=%v target=%s", err, remoteAddr, fallbackTarget),
			})
			s.handleFallback(ctx, conn, req, body, fallbackTarget, sni)
		}
		return err
	}
	if info.version != satlsVersion {
		_ = writeSwitchingProtocols(conn, "VersionMismatch")
		s.writeErrorResponse(conn, http.StatusUpgradeRequired, "VersionMismatch")
		return errVersionMismatch
	}
	_ = conn.SetReadDeadline(time.Time{})
	cached := newCachedConn(conn, reader)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.Name = protocolName
		inbound.User = info.user
	}
	switch info.mode {
	case linkModeFull:
		return s.handleFull(ctx, cached, info, dispatcher)
	case linkModeUp:
		return s.handleSplitUp(ctx, cached, info, dispatcher)
	case linkModeDown:
		return s.handleSplitDown(ctx, cached, info)
	default:
		return stderrs.New("satls: unsupported link mode")
	}
}

func (s *Server) acceptTLS(raw net.Conn) (net.Conn, string, error) {
	serverConf := s.tlsConfig.Clone()
	var clientSNI string
	serverConf.GetConfigForClient = func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
		clientSNI = ch.ServerName
		// Select cert based on SNI and link hints
		if s.upCertFile != "" && s.upKeyFile != "" && sniMatches(ch.ServerName, s.upServerName) {
			if cert, err := tls.LoadX509KeyPair(s.upCertFile, s.upKeyFile); err == nil {
				conf := serverConf.Clone()
				conf.Certificates = []tls.Certificate{cert}
				return conf, nil
			}
		}
		if s.downCertFile != "" && s.downKeyFile != "" && sniMatches(ch.ServerName, s.downServerName) {
			if cert, err := tls.LoadX509KeyPair(s.downCertFile, s.downKeyFile); err == nil {
				conf := serverConf.Clone()
				conf.Certificates = []tls.Certificate{cert}
				return conf, nil
			}
		}
		return serverConf, nil
	}
	conn := tls.Server(raw, serverConf)
	if err := conn.Handshake(); err != nil {
		return nil, "", err
	}
	state := conn.ConnectionState()
	if state.ServerName != "" {
		clientSNI = state.ServerName
	}
	return conn, clientSNI, nil
}

type handshakeRequest struct {
	path      string
	user      *protocol.MemoryUser
	sessionID string
	mode      linkMode
	reconnect bool
	version   string
	sni       string
}

func (s *Server) handleFallback(ctx context.Context, conn net.Conn, req *http.Request, body []byte, targetHost string, sni string) {
	if req != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		if len(body) > 0 {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
	}
	if err := s.proxyFallback(ctx, conn, req, targetHost, sni); err != nil {
		s.sleepFallbackDelay()
		s.writeErrorResponse(conn, http.StatusBadRequest, "")
	}
}

func (s *Server) validateRequest(req *http.Request, bodyLen int, sni string) (*handshakeRequest, error) {
	if !strings.EqualFold(req.Method, "SATLS") {
		return nil, stderrs.New("satls: invalid method")
	}
	pathToken := normalizePathToken(req.URL.Path)
	if pathToken == "" {
		return nil, stderrs.New("satls: missing path")
	}
	user := s.findUser(pathToken)
	if user == nil {
		return nil, stderrs.New("satls: unknown path")
	}
	mode, err := parseLinkMode(req.Header.Get("S-Link-Mode"))
	if err != nil {
		return nil, err
	}
	sessionID, err := parseSessionID(req.Header.Get("S-Session-ID"))
	if err != nil {
		return nil, err
	}
	var reconnect bool
	if v := req.Header.Get("S-Reconnect"); v != "" {
		value, ok := parseBoolHeader(v)
		if !ok {
			return nil, stderrs.New("satls: invalid S-Reconnect header")
		}
		reconnect = value
	}
	if bodyLen < 0 {
		return nil, stderrs.New("satls: missing padding length")
	}
	if bodyLen > maxPaddingSize {
		return nil, stderrs.New("satls: padding too large")
	}
	if s.rejectUnknown {
		allowed := s.serverName
		if mode == linkModeUp && s.upServerName != "" {
			allowed = s.upServerName
		} else if mode == linkModeDown && s.downServerName != "" {
			allowed = s.downServerName
		}
		sniLower := strings.ToLower(strings.TrimSpace(sni))
		if allowed != "" {
			if sniLower == "" || sniLower != allowed {
				return nil, stderrs.New("satls: sni mismatch")
			}
		}
	}
	return &handshakeRequest{
		path:      pathToken,
		user:      user,
		sessionID: sessionID,
		mode:      mode,
		reconnect: reconnect,
		version:   strings.TrimSpace(req.Header.Get("S-Version")),
		sni:       sni,
	}, nil
}

func (s *Server) findUser(path string) *protocol.MemoryUser {
	snap := s.loadStore()
	return snap.users[hashPath(path)]
}

func (s *Server) handleFull(ctx context.Context, conn net.Conn, info *handshakeRequest, dispatcher routing.Dispatcher) error {
	if !s.replay.Reserve(info.sessionID) {
		s.handleFallback(ctx, conn, nil, nil, s.fallbackHost(info), info.sni)
		return stderrs.New("satls: duplicate session id")
	}
	// FULL 链路返回 101
	if err := writeSwitchingProtocols(conn, "Established"); err != nil {
		return err
	}
	return s.runMux(ctx, conn, info.user, dispatcher)
}

func (s *Server) handleSplitUp(ctx context.Context, conn net.Conn, info *handshakeRequest, dispatcher routing.Dispatcher) error {
	if info.reconnect {
		return stderrs.New("satls: reconnect on up link")
	}
	if !s.replay.Reserve(info.sessionID) {
		s.handleFallback(ctx, conn, nil, nil, s.fallbackHost(info), info.sni)
		return stderrs.New("satls: duplicate session id")
	}
	session := newSplitSession(info.sessionID, info.user, conn)
	s.sessionsMu.Lock()
	if _, exists := s.splitSessions[info.sessionID]; exists {
		s.sessionsMu.Unlock()
		s.writeErrorResponse(conn, http.StatusConflict, "session exists")
		return stderrs.New("satls: session exists")
	}
	s.splitSessions[info.sessionID] = session
	s.sessionsMu.Unlock()
	session.startTimeout(func() {
		s.finishSplitSession(info.sessionID, stderrs.New("satls: timeout waiting for down link"))
	})
	var runErr error
	defer func() {
		s.finishSplitSession(info.sessionID, runErr)
	}()
	if err := session.waitReady(ctx); err != nil {
		runErr = err
		return err
	}
	combined := session.combinedConn()
	if combined == nil {
		runErr = session.Err()
		return runErr
	}
	runErr = s.runMux(ctx, combined, info.user, dispatcher)
	return runErr
}

func (s *Server) handleSplitDown(ctx context.Context, conn net.Conn, info *handshakeRequest) error {
	s.sessionsMu.Lock()
	session, ok := s.splitSessions[info.sessionID]
	s.sessionsMu.Unlock()
	if !ok {
		s.handleFallback(ctx, conn, nil, nil, s.fallbackHost(info), info.sni)
		return stderrs.New("satls: unknown session")
	}
	// reconnect allowed, handled by attachDown
	status, errAttach := session.attachDown(conn, info.reconnect)
	if errAttach != nil {
		s.writeErrorResponse(conn, http.StatusConflict, errAttach.Error())
		return errAttach
	}
	if err := writeSwitchingProtocols(conn, status); err != nil {
		return err
	}
	<-session.done
	return session.Err()
}

func (s *Server) finishSplitSession(id string, err error) {
	s.sessionsMu.Lock()
	session, ok := s.splitSessions[id]
	if ok {
		delete(s.splitSessions, id)
	}
	s.sessionsMu.Unlock()
	if ok {
		session.close(err)
	}
}

func (s *Server) writeErrorResponse(w io.Writer, code int, status string) {
	if status == "" {
		status = http.StatusText(code)
	}
	msg := fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", code, status)
	_, _ = io.WriteString(w, msg)
}

func writeSwitchingProtocols(w io.Writer, status string) error {
	if status == "" {
		status = "Established"
	}
	response := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: smux-v2\r\nConnection: Upgrade\r\nS-Session-Status: %s\r\n\r\n", status)
	_, err := io.WriteString(w, response)
	return err
}

func (s *Server) runMux(ctx context.Context, conn net.Conn, user *protocol.MemoryUser, dispatcher routing.Dispatcher) error {
	smuxSession, err := smux.Server(conn, satlsSmuxConfig())
	if err != nil {
		return err
	}
	defer smuxSession.Close()
	for {
		stream, err := smuxSession.AcceptStream()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		go s.handleStream(ctx, user, stream, dispatcher)
	}
}

func (s *Server) handleStream(ctx context.Context, user *protocol.MemoryUser, stream net.Conn, dispatcher routing.Dispatcher) {
	defer stream.Close()
	reader := &buf.BufferedReader{Reader: buf.NewReader(stream)}
	writer := buf.NewBufferedWriter(buf.NewWriter(stream))
	dest, err := readDestinationMetadata(reader)
	if err != nil {
		writer.WriteByte(0xEE)
		_ = writer.Flush()
		return
	}
	sessPolicy := s.policyManager.ForLevel(user.Level)
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(subCtx, cancel, sessPolicy.Timeouts.ConnectionIdle)
	ctx = log.ContextWithAccessMessage(subCtx, &log.AccessMessage{
		From:   stream.RemoteAddr(),
		To:     dest,
		Email:  user.Email,
		Status: log.AccessAccepted,
	})
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		writer.WriteByte(0xEE)
		_ = writer.Flush()
		return
	}
	writer.WriteByte(0x00)
	if err := writer.Flush(); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return
	}
	requestDone := func() error {
		defer timer.SetTimeout(sessPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessPolicy.Timeouts.UplinkOnly)
		return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
	}
	if err := task.Run(ctx, task.OnSuccess(requestDone, task.Close(link.Writer)), responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	}
}

func satlsSmuxConfig() *smux.Config {
	conf := smux.DefaultConfig()
	conf.Version = 2
	conf.KeepAliveInterval = 30 * time.Second
	conf.KeepAliveTimeout = 90 * time.Second
	return conf
}

type sessionIDCache struct {
	mu    sync.Mutex
	items map[string]time.Time
}

func newSessionIDCache() *sessionIDCache {
	return &sessionIDCache{items: make(map[string]time.Time)}
}

func (c *sessionIDCache) Reserve(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for key, expiry := range c.items {
		if now.After(expiry) {
			delete(c.items, key)
		}
	}
	if expiry, ok := c.items[id]; ok && now.Before(expiry) {
		return false
	}
	c.items[id] = now.Add(sessionReplayTTL)
	return true
}

type splitSession struct {
	id          string
	user        *protocol.MemoryUser
	upConn      net.Conn
	downMu      sync.Mutex
	downConn    net.Conn
	ready       chan struct{}
	done        chan struct{}
	readyOnce   sync.Once
	doneOnce    sync.Once
	timerMu     sync.Mutex
	timer       *time.Timer
	pausedTimer *time.Timer
	errMu       sync.Mutex
	err         error
	buffer      bytes.Buffer
	bufferCap   int
	state       splitState
}

func newSplitSession(id string, user *protocol.MemoryUser, up net.Conn) *splitSession {
	return &splitSession{
		id:        id,
		user:      user,
		upConn:    up,
		ready:     make(chan struct{}),
		done:      make(chan struct{}),
		bufferCap: 2 * 1024 * 1024,
		state:     splitStateWaiting,
	}
}

type splitState int

const (
	splitStateWaiting splitState = iota
	splitStateActive
	splitStatePaused
	splitStateClosed
)

func (s *splitSession) startTimeout(onTimeout func()) {
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	s.timer = time.AfterFunc(splitDownTimeout, onTimeout)
}

func (s *splitSession) attachDown(conn net.Conn, reconnect bool) (string, error) {
	s.downMu.Lock()
	defer s.downMu.Unlock()
	status := "Established"
	s.stopTimer()
	if s.pausedTimer != nil {
		s.pausedTimer.Stop()
		s.pausedTimer = nil
	}
	switch s.state {
	case splitStateWaiting:
		if reconnect {
			return status, stderrs.New("satls: unexpected reconnect while waiting")
		}
	case splitStatePaused:
		if !reconnect {
			return status, stderrs.New("satls: reconnect expected")
		}
		status = "Reconnected"
	case splitStateActive:
		if s.downConn != nil {
			return status, stderrs.New("satls: down link already attached")
		}
	default:
		return status, stderrs.New("satls: session closed")
	}
	s.downConn = conn
	s.state = splitStateActive
	s.notifyReady()
	if s.buffer.Len() > 0 {
		if err := s.flushBufferLocked(); err != nil {
			s.enterPausedLocked(err)
			return status, err
		}
	}
	return status, nil
}

func (s *splitSession) combinedConn() net.Conn {
	s.downMu.Lock()
	defer s.downMu.Unlock()
	if s.downConn == nil || s.upConn == nil {
		return nil
	}
	return &splitConn{session: s}
}

func (s *splitSession) writeDown(p []byte) (int, error) {
	s.downMu.Lock()
	defer s.downMu.Unlock()
	if s.state == splitStateClosed {
		return 0, io.EOF
	}
	if s.downConn == nil {
		if s.buffer.Len()+len(p) > s.bufferCap {
			err := stderrs.New("satls: down buffer overflow")
			go s.close(err)
			return 0, err
		}
		s.buffer.Write(p)
		return len(p), nil
	}
	n, err := s.downConn.Write(p)
	if err != nil {
		s.enterPausedLocked(err)
		if n < len(p) {
			remaining := p[n:]
			if s.buffer.Len()+len(remaining) > s.bufferCap {
				overflow := stderrs.New("satls: down buffer overflow")
				go s.close(overflow)
				return n, overflow
			}
			s.buffer.Write(remaining)
		}
		return len(p), nil
	}
	return n, nil
}

func (s *splitSession) flushBufferLocked() error {
	if s.downConn == nil {
		return nil
	}
	if s.buffer.Len() == 0 {
		return nil
	}
	reader := bytes.NewReader(s.buffer.Bytes())
	if _, err := io.Copy(s.downConn, reader); err != nil {
		return err
	}
	s.buffer.Reset()
	return nil
}

func (s *splitSession) waitReady(ctx context.Context) error {
	select {
	case <-s.ready:
		s.downMu.Lock()
		ready := s.downConn != nil
		s.downMu.Unlock()
		if !ready {
			return s.Err()
		}
		return nil
	case <-s.done:
		return s.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *splitSession) notifyReady() {
	s.readyOnce.Do(func() { close(s.ready) })
}

func (s *splitSession) close(err error) {
	s.setErr(err)
	s.stopTimer()
	s.state = splitStateClosed
	s.notifyReady()
	s.doneOnce.Do(func() { close(s.done) })
	if s.upConn != nil {
		_ = s.upConn.Close()
		s.upConn = nil
	}
	s.downMu.Lock()
	if s.downConn != nil {
		_ = s.downConn.Close()
		s.downConn = nil
	}
	if s.pausedTimer != nil {
		s.pausedTimer.Stop()
		s.pausedTimer = nil
	}
	s.downMu.Unlock()
}

func (s *splitSession) stopTimer() {
	s.timerMu.Lock()
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.timerMu.Unlock()
}

func (s *splitSession) enterPausedLocked(err error) {
	if s.downConn != nil {
		_ = s.downConn.Close()
		s.downConn = nil
	}
	if s.state == splitStateClosed {
		return
	}
	s.state = splitStatePaused
	s.setErr(err)
	if s.pausedTimer != nil {
		s.pausedTimer.Stop()
	}
	s.pausedTimer = time.AfterFunc(30*time.Second, func() {
		s.close(stderrs.New("satls: reconnect timeout"))
	})
}

func (s *splitSession) setErr(err error) {
	s.errMu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.errMu.Unlock()
}

func (s *splitSession) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

type splitConn struct {
	session *splitSession
}

func (c *splitConn) Read(p []byte) (int, error) {
	return c.session.upConn.Read(p)
}

func (c *splitConn) Write(p []byte) (int, error) {
	return c.session.writeDown(p)
}

func (c *splitConn) Close() error {
	err1 := c.session.upConn.Close()
	c.session.downMu.Lock()
	if c.session.downConn != nil {
		_ = c.session.downConn.Close()
	}
	c.session.downMu.Unlock()
	if err1 != nil {
		return err1
	}
	return nil
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.session.upConn.LocalAddr()
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.session.upConn.RemoteAddr()
}

func (c *splitConn) SetDeadline(t time.Time) error {
	if err := c.session.upConn.SetDeadline(t); err != nil {
		return err
	}
	c.session.downMu.Lock()
	if c.session.downConn != nil {
		_ = c.session.downConn.SetDeadline(t)
	}
	c.session.downMu.Unlock()
	return nil
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	return c.session.upConn.SetReadDeadline(t)
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	c.session.downMu.Lock()
	defer c.session.downMu.Unlock()
	if c.session.downConn != nil {
		return c.session.downConn.SetWriteDeadline(t)
	}
	return nil
}

func (s *Server) proxyFallback(ctx context.Context, clientConn net.Conn, req *http.Request, targetHost string, sni string) error {
	resolveHost := strings.TrimSpace(targetHost)
	if resolveHost == "" && req != nil {
		resolveHost = req.Host
		if resolveHost == "" && req.URL != nil {
			resolveHost = req.URL.Host
		}
	}
	if resolveHost == "" {
		return stderrs.New("satls: fallback host missing")
	}
	hostHeader := strings.TrimSpace(sni)
	if hostHeader == "" && req != nil {
		hostHeader = strings.TrimSpace(req.Host)
		if hostHeader == "" && req.URL != nil {
			hostHeader = strings.TrimSpace(req.URL.Host)
		}
	}
	if hostHeader == "" {
		hostHeader = resolveHost
	}
	// resolve target host to IP and connect directly
	ipAddrs, err := net.DefaultResolver.LookupIP(ctx, "ip", resolveHost)
	if err != nil || len(ipAddrs) == 0 {
		return stderrs.New("satls: fallback resolve failed")
	}
	ip := ipAddrs[0].String()
	forwardURL := &url.URL{Scheme: "https", Host: hostHeader, Path: "/"}
	forwardReq, err := http.NewRequestWithContext(ctx, http.MethodGet, forwardURL.String(), nil)
	if err != nil {
		return err
	}
	forwardReq.Host = hostHeader
	// try to mimic browser-ish TLS/headers
	forwardReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	forwardReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	forwardReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	forwardReq.Header.Set("Connection", "close")

	transport := *s.fallbackClient.Transport.(*http.Transport)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	}
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS13
	transport.TLSClientConfig.MaxVersion = tls.VersionTLS13
	transport.TLSClientConfig.ServerName = hostHeader
	client := &http.Client{Timeout: s.fallbackClient.Timeout, Transport: &transport}

	resp, err := client.Do(forwardReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bufferedWriter := bufio.NewWriter(clientConn)
	if _, err := fmt.Fprintf(bufferedWriter, "HTTP/1.1 %s\r\n", resp.Status); err != nil {
		return err
	}
	headers := resp.Header.Clone()
	headers.Set("Connection", "close")
	if err := headers.Write(bufferedWriter); err != nil {
		return err
	}
	if _, err := bufferedWriter.WriteString("\r\n"); err != nil {
		return err
	}
	if _, err := io.Copy(bufferedWriter, resp.Body); err != nil {
		return err
	}
	return bufferedWriter.Flush()
}

func (s *Server) sleepFallbackDelay() {
	delay := time.Duration(50+rand.Intn(150)) * time.Millisecond
	time.Sleep(delay)
}

// errVersionMismatch signals S-Version mismatch for 426 handling.
var errVersionMismatch = stderrs.New("satls: version mismatch")

func (s *Server) fallbackHost(info *handshakeRequest) string {
	if info != nil {
		switch info.mode {
		case linkModeUp:
			if s.upServerName != "" {
				return s.upServerName
			}
			if info.sni != "" {
				return strings.TrimSpace(info.sni)
			}
			return ""
		case linkModeDown:
			if s.downServerName != "" {
				return s.downServerName
			}
			if s.upServerName != "" {
				return s.upServerName
			}
			if info.sni != "" {
				return strings.TrimSpace(info.sni)
			}
			return ""
		}
	}
	if split := s.splitDefaultHost(); split != "" {
		return split
	}
	return s.serverName
}

func (s *Server) pickFallbackTarget(req *http.Request, sni string) string {
	var target string
	splitDefault := s.splitDefaultHost()
	splitConfigured := splitDefault != ""
	splitted := false
	if req != nil {
		if mode, err := parseLinkMode(req.Header.Get("S-Link-Mode")); err == nil {
			switch mode {
			case linkModeUp:
				splitted = true
				if s.upServerName != "" {
					target = s.upServerName
				}
			case linkModeDown:
				splitted = true
				if s.downServerName != "" {
					target = s.downServerName
				} else if s.upServerName != "" {
					target = s.upServerName
				}
			}
		}
	}
	if target == "" && splitConfigured {
		target = splitDefault
	}
	if target == "" && req != nil {
		target = strings.TrimSpace(req.Host)
		if target == "" && req.URL != nil {
			target = strings.TrimSpace(req.URL.Host)
		}
	}
	if target == "" {
		target = strings.TrimSpace(sni)
	}
	if target == "" && !splitted && !splitConfigured {
		target = s.serverName
	}
	return target
}

func (s *Server) splitDefaultHost() string {
	if s.upServerName != "" {
		return s.upServerName
	}
	if s.downServerName != "" {
		return s.downServerName
	}
	return s.serverName
}
