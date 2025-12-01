## Suggested Commands
- Format Go files: `gofmt -w <files>`
- Run package tests (uses local cache to avoid permission issues): `GOCACHE=$(pwd)/.gocache go test ./...`
- Quick package check without full tree: `GOCACHE=$(pwd)/.gocache go test ./proxy/satls`
- Build release binary (from README): `GOEXPERIMENT=jsonv2 go build -v -o build_assets/v2node -trimpath -ldflags "-X 'github.com/wyx2685/v2node/cmd.version=$version' -s -w -buildid="`
- Install script (if needed): `wget -N https://raw.githubusercontent.com/wyx2685/v2node/master/script/install.sh && bash install.sh`