package satls

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

func TestUserManagerHotUpdatesPreserveExistingPaths(t *testing.T) {
	server := &Server{
		pendingAdds:    make(map[string]*protocol.MemoryUser),
		pendingRemoves: make(map[string]struct{}),
		updateCh:       make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
		debounce:       time.Millisecond,
	}
	server.store.Store(&userStoreSnapshot{
		users:      make(map[[32]byte]*protocol.MemoryUser),
		emailIndex: make(map[string][32]byte),
	})

	stopped := make(chan struct{})
	go func() {
		server.userUpdaterLoop()
		close(stopped)
	}()
	t.Cleanup(func() {
		close(server.stopCh)
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Error("SATLS user updater did not stop")
		}
	})

	ctx := context.Background()
	existing := &protocol.MemoryUser{
		Email:   "satls-node|0198f31d-5228-75f1-bceb-5ee9848f7fd7",
		Account: &MemoryAccount{Path: "0198f31d-5228-75f1-bceb-5ee9848f7fd7"},
	}
	if err := server.AddUser(ctx, existing); err != nil {
		t.Fatalf("add existing user: %v", err)
	}
	waitForSATLSUsers(t, server, 1, func() bool {
		return server.GetUser(ctx, existing.Email) == existing && server.findUser(existing.Account.(*MemoryAccount).Path) == existing
	})

	added := &protocol.MemoryUser{
		Email:   "satls-node|0198f31d-5228-75f1-bceb-5ee9848f7fd8",
		Account: &MemoryAccount{Path: "0198f31d-5228-75f1-bceb-5ee9848f7fd8"},
	}
	if err := server.AddUser(ctx, added); err != nil {
		t.Fatalf("hot-add user: %v", err)
	}
	waitForSATLSUsers(t, server, 2, func() bool {
		return server.GetUser(ctx, existing.Email) == existing &&
			server.findUser(existing.Account.(*MemoryAccount).Path) == existing &&
			server.GetUser(ctx, added.Email) == added &&
			server.findUser(added.Account.(*MemoryAccount).Path) == added
	})

	if err := server.RemoveUser(ctx, existing.Email); err != nil {
		t.Fatalf("hot-remove user: %v", err)
	}
	waitForSATLSUsers(t, server, 1, func() bool {
		return server.GetUser(ctx, existing.Email) == nil &&
			server.findUser(existing.Account.(*MemoryAccount).Path) == nil &&
			server.GetUser(ctx, added.Email) == added &&
			server.findUser(added.Account.(*MemoryAccount).Path) == added
	})
}

func waitForSATLSUsers(t *testing.T, server *Server, count int64, matches func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if server.GetUsersCount(context.Background()) == count && matches() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("SATLS users did not converge: count=%d want=%d", server.GetUsersCount(context.Background()), count)
}
