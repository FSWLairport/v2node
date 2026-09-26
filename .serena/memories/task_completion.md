## Task Completion Checklist
- Format Go changes with `gofmt -w <files>`.
- Run targeted tests with local cache: `GOCACHE=$(pwd)/.gocache go test ./...` (or narrower package).
- If building deliverable, use `GOEXPERIMENT=jsonv2 go build -v -o build_assets/v2node -trimpath -ldflags "-X 'github.com/wyx2685/v2node/cmd.version=$version' -s -w -buildid="`.
- Review for logging/metrics consistency (logrus).
- Document any config or TLS/SATLS behavior changes in notes/PR description.
- Clean up temporary caches or binaries if not needed.