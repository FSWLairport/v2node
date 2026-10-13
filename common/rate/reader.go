package rate

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"time"
)

type Reader struct {
	reader  buf.Reader
	limiter *DynamicBucket
}

func NewRateLimitReader(reader buf.Reader, limiter *DynamicBucket) buf.Reader {
	return &Reader{reader: reader, limiter: limiter}
}
func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if n := mb.Len(); n > 0 {
		r.limiter.Get().Wait(int64(n))
	}
	return mb, err
}
func (r *Reader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	reader := &buf.TimeoutWrapperReader{Reader: r.reader}
	mb, err := reader.ReadMultiBufferTimeout(timeout)
	if n := mb.Len(); n > 0 {
		r.limiter.Get().Wait(int64(n))
	}
	return mb, err
}
func (r *Reader) Close() error { return common.Close(r.reader) }
func (r *Reader) Interrupt()   { common.Interrupt(r.reader) }
