package panel

import (
	"runtime/debug"
	"strings"
)

// RuntimeNodeVersion is reported to the panel as a header on the config pull.
// The node already polls on a timer, so the running build needs no channel of
// its own: the panel records it alongside the node's liveness.
func RuntimeNodeVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	if version := strings.TrimSpace(info.Main.Version); version != "" && version != "(devel)" {
		return version
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" && setting.Value != "" {
			return setting.Value
		}
	}
	return "devel"
}
