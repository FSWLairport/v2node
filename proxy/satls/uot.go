package satls

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/features/routing"
)

// uotStreamConn adapts a SATLS smux stream into a net.Conn whose reads come from
// the already-buffered reader (so no bytes consumed during metadata/handshake
// parsing are lost), while writes/close/addresses fall through to the raw stream.
type uotStreamConn struct {
	net.Conn
	reader io.Reader
}

func (c *uotStreamConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// tryHandleUoT detects the UDP-over-TCP magic destination on a freshly opened
// SATLS stream. When matched, it performs the UoT handshake and bridges the
// stream to the xray dispatcher as a UDP packet connection, returning true to
// signal that the stream has been fully handled. Non-UoT streams return false
// so the caller continues with the normal TCP relay path.
func (s *Server) tryHandleUoT(
	ctx context.Context,
	user *protocol.MemoryUser,
	stream net.Conn,
	reader *buf.BufferedReader,
	writer *buf.BufferedWriter,
	dest xnet.Destination,
	dispatcher routing.Dispatcher,
) bool {
	if dest.Address == nil || !dest.Address.Family().IsDomain() {
		return false
	}
	domain := dest.Address.Domain()
	if domain != uot.MagicAddress {
		if domain == uot.LegacyMagicAddress {
			// The SATLS client only speaks UoT v2; refuse legacy magic explicitly.
			_ = writer.WriteByte(0xEE)
			_ = writer.Flush()
			return true
		}
		return false
	}

	userEmail := ""
	if user != nil {
		userEmail = user.Email
	}

	// Acknowledge the stream first (single 0x00), matching the SATLS client which
	// waits for the ack before writing the UoT request. Order is significant.
	if err := writer.WriteByte(0x00); err != nil {
		return true
	}
	if err := writer.Flush(); err != nil {
		return true
	}

	request, err := uot.ReadRequest(reader)
	if err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  fmt.Sprintf("satls uot: read request failed user=%s err=%v remote=%v", userEmail, err, stream.RemoteAddr()),
		})
		return true
	}

	requestDest, err := singbridge.ToDestination(request.Destination, xnet.Network_UDP)
	if err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  fmt.Sprintf("satls uot: invalid destination user=%s err=%v remote=%v", userEmail, err, stream.RemoteAddr()),
		})
		return true
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   stream.RemoteAddr(),
		To:     requestDest,
		Email:  userEmail,
		Status: log.AccessAccepted,
		Reason: "satls-uot",
	})

	link, err := dispatcher.Dispatch(ctx, requestDest)
	if err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  fmt.Sprintf("satls uot: dispatch failed dest=%s user=%s err=%v remote=%v", requestDest.String(), userEmail, err, stream.RemoteAddr()),
		})
		return true
	}

	// uot.Conn decodes/encodes the UDP datagram framing (length-prefixed, with
	// per-packet address in non-connect mode). Reads must go through the buffered
	// reader to preserve any bytes already pulled from the stream.
	packetConn := uot.NewConn(&uotStreamConn{Conn: stream, reader: reader}, *request)

	if err := singbridge.CopyPacketConn(ctx, stream, link, requestDest, packetConn); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  fmt.Sprintf("satls uot: stream closed dest=%s user=%s err=%v remote=%v", requestDest.String(), userEmail, err, stream.RemoteAddr()),
		})
	}
	return true
}
