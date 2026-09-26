package satls

import (
	"testing"

	"github.com/sagernet/smux"
)

func TestSATLSSmuxStreamWindowRaisedAboveLibraryDefault(t *testing.T) {
	if got, def := satlsSmuxConfig().MaxStreamBuffer, smux.DefaultConfig().MaxStreamBuffer; got <= def {
		t.Fatalf("MaxStreamBuffer = %d, must exceed the library default %d or high-RTT streams stall at window/RTT", got, def)
	}
}

func TestSATLSSmuxKeepAliveLeavesMarginOverSpecHeartbeat(t *testing.T) {
	conf := satlsSmuxConfig()
	// SATLS.md section 5 lets a conforming peer send NOP only every 30s, and smux
	// judges liveness on a fixed ticker rather than a timer reset by traffic,
	// so a read timeout at or near that interval kills healthy sessions on the
	// tick boundary.
	if conf.KeepAliveTimeout <= satlsSpecMaxNOPInterval {
		t.Fatalf("KeepAliveTimeout = %v, must exceed the %v heartbeat the spec permits",
			conf.KeepAliveTimeout, satlsSpecMaxNOPInterval)
	}
	if margin, want := conf.KeepAliveTimeout-satlsSpecMaxNOPInterval, satlsSpecMaxNOPInterval/2; margin < want {
		t.Fatalf("KeepAliveTimeout leaves only %v of margin over the spec heartbeat, want at least %v",
			margin, want)
	}
	// Sending slower than the spec allows would let a conforming peer time us out.
	if conf.KeepAliveInterval > satlsSpecMaxNOPInterval {
		t.Fatalf("KeepAliveInterval = %v, spec requires a NOP at least every %v",
			conf.KeepAliveInterval, satlsSpecMaxNOPInterval)
	}
}

func TestSATLSPairingTimeoutOutlivesClientRetryWindow(t *testing.T) {
	// The client gives up dialing DOWN before this fires (8s vs 10s) so its last
	// retry cannot race the server tearing the session down. Keep the gap.
	const clientRetryWindow = 8 // seconds, satls outbound splitDownRetryTimeout
	if splitDownTimeout.Seconds() <= clientRetryWindow {
		t.Fatalf("splitDownTimeout = %v, must outlast the client's %ds retry window",
			splitDownTimeout, clientRetryWindow)
	}
}
