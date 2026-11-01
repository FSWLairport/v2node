package dispatcher

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/userlease"
	"github.com/wyx2685/v2node/limiter"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

func TestConsumerExpiryClosesBothDirectionsAndRenewedStreams(t *testing.T) {
	tag := fmt.Sprintf("lease-stream-%d", time.Now().UnixNano())
	key := tag + "|customer"
	limiter.Init()
	limiter.AddLimiter("satls", tag, []panel.UserInfo{{Id: 1, Uuid: "customer"}, {Id: 2, Uuid: "enterprise"}}, nil)
	ctx := func(email string) context.Context {
		return session.ContextWithInbound(context.Background(), &session.Inbound{Tag: tag, User: &protocol.MemoryUser{Email: email}, Source: xnet.TCPDestination(xnet.LocalHostIP, 12345)})
	}
	d := &DefaultDispatcher{}
	userlease.Set(key, time.Now().Add(time.Minute), func() {
		if v, ok := d.LinkManagers.Load(key); ok {
			v.(*LinkManager).CloseAll()
		}
	})
	type pair struct{ in, out *transport.Link }
	links := make([]pair, 32)
	var wg sync.WaitGroup
	for i := range links {
		wg.Add(1)
		go func() {
			defer wg.Done()
			in, out, _, err := d.getLink(ctx(key))
			if err != nil {
				t.Error(err)
				return
			}
			links[i] = pair{in, out}
		}()
	}
	wg.Wait()
	bIn, bOut, _, err := d.getLink(ctx(tag + "|enterprise"))
	if err != nil {
		t.Fatal(err)
	}
	userlease.Revoke(key)
	deadline := time.Now().Add(time.Second)
	for userlease.Allowed(key) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for _, p := range links {
		if p.in == nil {
			t.Fatal("missing stream")
		}
		for _, r := range []buf.Reader{p.in.Reader, p.out.Reader} {
			done := make(chan error, 1)
			go func() { mb, err := r.ReadMultiBuffer(); buf.ReleaseMulti(mb); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("expired stream remained readable")
				}
			case <-time.After(time.Second):
				t.Fatal("expiry failed to interrupt a stream direction")
			}
		}
	}
	if _, _, _, err = d.getLink(ctx(key)); err == nil {
		t.Fatal("expired identity opened a new stream")
	}
	// A later successful reauthentication must be tracked by the same manager.
	userlease.Set(key, time.Now().Add(time.Minute), func() {
		if v, ok := d.LinkManagers.Load(key); ok {
			v.(*LinkManager).CloseAll()
		}
	})
	in, out, _, err := d.getLink(ctx(key))
	if err != nil {
		t.Fatal(err)
	}
	userlease.Revoke(key)
	done := make(chan error, 1)
	go func() { _, err := out.Reader.ReadMultiBuffer(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("renewed stream survived revocation")
		}
	case <-time.After(time.Second):
		t.Fatal("renewed stream was not registered")
	}
	_ = in.Writer
	// C revocation leaves the enterprise user's pipes usable.
	b := buf.New()
	b.Write([]byte("enterprise"))
	if err := bIn.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
	mb, err := bOut.Reader.ReadMultiBuffer()
	if err != nil || mb.Len() != 10 {
		t.Fatalf("enterprise stream affected: %d %v", mb.Len(), err)
	}
	buf.ReleaseMulti(mb)
}
