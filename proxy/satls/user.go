package satls

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

type userStoreSnapshot struct {
	users      map[[32]byte]*protocol.MemoryUser
	emailIndex map[string][32]byte
}

func (s *Server) loadStore() *userStoreSnapshot {
	v := s.store.Load()
	if v == nil {
		empty := &userStoreSnapshot{
			users:      make(map[[32]byte]*protocol.MemoryUser),
			emailIndex: make(map[string][32]byte),
		}
		s.store.Store(empty)
		return empty
	}
	return v.(*userStoreSnapshot)
}

// AddUser implements proxy.UserManager.
func (s *Server) AddUser(ctx context.Context, mu *protocol.MemoryUser) error {
	if mu == nil || mu.Account == nil {
		return errors.New("satls: invalid user")
	}
	if _, ok := mu.Account.(*MemoryAccount); !ok {
		return errors.New("satls: invalid account type")
	}
	s.pendingMu.Lock()
	delete(s.pendingRemoves, mu.Email)
	s.pendingAdds[mu.Email] = mu
	s.pendingMu.Unlock()
	s.scheduleUserUpdate()
	return nil
}

// RemoveUser implements proxy.UserManager.
func (s *Server) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("satls: empty email")
	}
	s.pendingMu.Lock()
	delete(s.pendingAdds, email)
	s.pendingRemoves[email] = struct{}{}
	s.pendingMu.Unlock()
	s.scheduleUserUpdate()
	return nil
}

// GetUser implements proxy.UserManager.
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}
	snap := s.loadStore()
	if sum, ok := snap.emailIndex[email]; ok {
		return snap.users[sum]
	}
	return nil
}

// GetUsers implements proxy.UserManager.
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	snap := s.loadStore()
	users := make([]*protocol.MemoryUser, 0, len(snap.users))
	for _, mu := range snap.users {
		users = append(users, mu)
	}
	return users
}

// GetUsersCount implements proxy.UserManager.
func (s *Server) GetUsersCount(ctx context.Context) int64 {
	return int64(len(s.loadStore().users))
}

func (s *Server) scheduleUserUpdate() {
	select {
	case s.updateCh <- struct{}{}:
	default:
	}
}

func (s *Server) userUpdaterLoop() {
	var timer *time.Timer
	for {
		var timerC <-chan time.Time
		if timer != nil {
			timerC = timer.C
		}
		select {
		case <-s.stopCh:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-s.updateCh:
			if timer == nil {
				timer = time.NewTimer(s.debounce)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(s.debounce)
			}
		case <-timerC:
			timer.Stop()
			timer = nil
			s.applyPending()
		}
	}
}

func (s *Server) applyPending() {
	s.pendingMu.Lock()
	adds := make(map[string]*protocol.MemoryUser, len(s.pendingAdds))
	for email, mu := range s.pendingAdds {
		adds[email] = mu
	}
	removes := make(map[string]struct{}, len(s.pendingRemoves))
	for email := range s.pendingRemoves {
		removes[email] = struct{}{}
	}
	s.pendingAdds = make(map[string]*protocol.MemoryUser)
	s.pendingRemoves = make(map[string]struct{})
	s.pendingMu.Unlock()

	if len(adds) == 0 && len(removes) == 0 {
		return
	}

	s.wmu.Lock()
	defer s.wmu.Unlock()
	old := s.loadStore()
	newUsers := make(map[[32]byte]*protocol.MemoryUser, len(old.users)+len(adds))
	for k, v := range old.users {
		newUsers[k] = v
	}
	newEmail := make(map[string][32]byte, len(old.emailIndex))
	for k, v := range old.emailIndex {
		newEmail[k] = v
	}

	for email := range removes {
		if sum, ok := newEmail[email]; ok {
			delete(newEmail, email)
			delete(newUsers, sum)
		}
	}

	for email, mu := range adds {
		acc, ok := mu.Account.(*MemoryAccount)
		if !ok {
			continue
		}
		sum := hashPath(acc.Path)
		if prev, ok := newEmail[email]; ok && prev != sum {
			delete(newUsers, prev)
		}
		newUsers[sum] = mu
		newEmail[email] = sum
	}

	s.store.Store(&userStoreSnapshot{users: newUsers, emailIndex: newEmail})
}
