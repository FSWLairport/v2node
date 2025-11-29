package satls

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount keeps the normalized SATLS path token for a user.
type MemoryAccount struct {
	Path string
}

func (a *Account) AsAccount() (protocol.Account, error) {
	path := normalizePathToken(a.GetPath())
	if path == "" {
		return nil, errors.New("satls: empty path token")
	}
	return &MemoryAccount{Path: path}, nil
}

func (m *MemoryAccount) Equals(other protocol.Account) bool {
	o, ok := other.(*MemoryAccount)
	return ok && m.Path == o.Path
}

func (m *MemoryAccount) ToProto() proto.Message {
	return &Account{Path: m.Path}
}
