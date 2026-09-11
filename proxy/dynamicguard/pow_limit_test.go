package dynamicguard

import (
	"strings"
	"testing"
)

func TestServerRejectsExcessivePoWBeforeStartup(t *testing.T) {
	_, err := NewDGServer(&DGServerConfig{DGSettings: &DGSettings{PowDifficulty: 25}})
	if err == nil || !strings.Contains(err.Error(), "pow_difficulty") {
		t.Fatalf("got %v", err)
	}
}
