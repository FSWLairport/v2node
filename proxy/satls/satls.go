package satls

import (
	"context"
	"math/rand"
	"time"

	"github.com/xtls/xray-core/common"
)

func init() {
	rand.Seed(time.Now().UnixNano())
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewServer(ctx, cfg.(*ServerConfig))
	}))
}
