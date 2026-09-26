package core

import (
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
)

// A node given an egress address or a fwmark gets its own freedom outbound and
// a catch-all rule onto it; listen_ip alone changes nothing (v2board sets it
// for the inbound), and a dynamicguard node never gets one.
func TestCustomConfigAddsPerNodeEgress(t *testing.T) {
	infos := []*panel.NodeInfo{
		{Tag: "pinned", Common: &panel.CommonNode{Protocol: "satls", ListenIP: "0.0.0.0", EgressIPv4: "203.0.113.7"}},
		{Tag: "listen", Common: &panel.CommonNode{Protocol: "satls", ListenIP: "203.0.113.6"}},
		{Tag: "marked", Common: &panel.CommonNode{Protocol: "satls", ListenIP: "0.0.0.0", EgressFwmark: 0x66}},
		{Tag: "plain", Common: &panel.CommonNode{Protocol: "satls", ListenIP: "::"}},
		{Tag: "dg", Common: &panel.CommonNode{Protocol: "dynamicguard", ListenIP: "203.0.113.8"}},
		{Tag: "dual", Common: &panel.CommonNode{Protocol: "satls", ListenIP: "0.0.0.0", EgressIPv4: "203.0.113.9", EgressIPv6: "2001:db8::9"}},
	}
	_, outbounds, router, err := GetCustomConfig(infos)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"egress-pinned", "egress-marked", "egress-dual-v4", "egress-dual-v6"} {
		if !hasOutboundWithTag(outbounds, tag) {
			t.Fatalf("missing outbound %s", tag)
		}
	}
	for _, tag := range []string{"egress-plain", "egress-listen", "egress-dg"} {
		if hasOutboundWithTag(outbounds, tag) {
			t.Fatalf("unexpected outbound %s", tag)
		}
	}
	// dns rule + two single egress rules + one per family for dual
	if got := len(router.Rule); got != 5 {
		t.Fatalf("router rules=%d, want 5", got)
	}
	// Domain destinations must be resolved to reach the per-family rules.
	if router.DomainStrategy.String() != "IpIfNonMatch" {
		t.Fatalf("domainStrategy=%s", router.DomainStrategy)
	}
}
