package dispatcher

import (
	"context"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/counter"
	"github.com/wyx2685/v2node/common/format"
	"github.com/wyx2685/v2node/common/rate"
	"github.com/wyx2685/v2node/limiter"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"sync"
	"testing"
	"time"
)

func TestGetLinkEnforcesOrganizationAlongsideUUIDAndSeparatesDirections(t *testing.T) {
	limiter.Init()
	const tag = "org-test"
	users := []panel.UserInfo{{Id: 1, Uuid: "a", OrgID: 7, SpeedLimit: 10}, {Id: 2, Uuid: "b", OrgID: 7}, {Id: 3, Uuid: "c", OrgID: 8}}
	l := limiter.AddLimiter("satls", tag, users, map[int]int{})
	defer limiter.DeleteLimiter(tag)
	l.OrgLimiter = rate.NewOrganizationLimiter(map[int]rate.BandwidthLimit{7: {UpMbps: 1, DownMbps: 2}, 8: {UpMbps: 1}})
	start := time.Now()
	d := &DefaultDispatcher{}
	for _, user := range users {
		email := format.UserTag(tag, user.Uuid)
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: tag, User: &protocol.MemoryUser{Email: email}, Source: net.TCPDestination(net.LocalHostIP, 1234)})
		in, out, _, err := d.getLink(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = in.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(make([]byte, 100))}); err != nil {
			t.Fatal(err)
		}
		if err = out.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(make([]byte, 200))}); err != nil {
			t.Fatal(err)
		}
		common.Close(in.Writer)
		common.Close(out.Writer)
		common.Interrupt(in.Reader)
		common.Interrupt(out.Reader)
	}
	up, down := l.OrgLimiter.Buckets(7)
	if !withinRefill(up.Get().Available(), 125000-200, 125000, start) || !withinRefill(down.Get().Available(), 250000-400, 250000, start) {
		t.Fatal("credentials did not share directional org limits")
	}
	uuid, _ := l.CheckLimit(format.UserTag(tag, "a"), "127.0.0.1", true)
	if uuid.Get().Available() != 1250000-300 {
		t.Fatal("legacy UUID limit did not apply alongside org limits")
	}
	other, _ := l.OrgLimiter.Buckets(8)
	if !withinRefill(other.Get().Available(), 125000-100, 125000, start) {
		t.Fatal("orgs share a bucket")
	}
}

func withinRefill(actual, expected, bytesPerSecond int64, start time.Time) bool {
	return actual >= expected && actual <= expected+int64(float64(bytesPerSecond)*time.Since(start).Seconds())+2
}

func TestConcurrentLinksStayInOneRevocationManager(t *testing.T) {
	limiter.Init()
	const tag = "concurrent-revoke"
	l := limiter.AddLimiter("satls", tag, []panel.UserInfo{{Id: 1, Uuid: "a"}}, map[int]int{})
	defer limiter.DeleteLimiter(tag)
	email := format.UserTag(tag, "a")
	d := &DefaultDispatcher{}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: tag, User: &protocol.MemoryUser{Email: email}, Source: net.TCPDestination(net.LocalHostIP, 1234)})
			in, _, _, err := d.getLink(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			if err := in.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("x"))}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	value, ok := d.LinkManagers.Load(email)
	if !ok {
		t.Fatal("missing manager")
	}
	manager := value.(*LinkManager)
	manager.mu.RLock()
	count := len(manager.links)
	manager.mu.RUnlock()
	if count != 64 {
		t.Fatalf("revocation tracks %d of 64 stream directions", count)
	}
	storedCounter, _ := d.Counter.Load(tag)
	if got := storedCounter.(*counter.TrafficCounter).GetUpCount(email); got != 32 {
		t.Fatalf("concurrent streams recorded %d of 32 bytes", got)
	}
	l.UserLimitInfo.Delete(email)
	manager.CloseAll()
	// A stream racing with removal must also be closed rather than left untracked.
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: tag, User: &protocol.MemoryUser{Email: email}, Source: net.TCPDestination(net.LocalHostIP, 1234)})
	in, _, _, err := d.getLink(ctx)
	if err != nil {
		return
	}
	if err = in.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("revoked"))}); err == nil {
		t.Fatal("stream escaped a closed revocation manager")
	}
}

func TestDispatchRacingWithCredentialRemovalCannotKeepAnOpenLink(t *testing.T) {
	limiter.Init()
	const tag = "racing-revoke"
	l := limiter.AddLimiter("satls", tag, []panel.UserInfo{{Id: 1, Uuid: "a"}}, map[int]int{})
	defer limiter.DeleteLimiter(tag)
	email := format.UserTag(tag, "a")
	d := &DefaultDispatcher{}
	links := make(chan *transport.Link, 128)
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: tag, User: &protocol.MemoryUser{Email: email}, Source: net.TCPDestination(net.LocalHostIP, 1234)})
			in, _, _, err := d.getLink(ctx)
			if err == nil {
				links <- in
			}
		}()
	}
	l.UserLimitInfo.Delete(email)
	if value, ok := d.LinkManagers.Load(email); ok {
		value.(*LinkManager).CloseAll()
		d.LinkManagers.Delete(email)
	}
	wg.Wait()
	close(links)
	for link := range links {
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("revoked"))}); err == nil {
			t.Fatal("a stream stayed open after credential removal")
		}
	}
}
