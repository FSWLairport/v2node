## Project Overview
- Purpose: V2board backend node built on modified xray-core (SATLS inbound, splitter, etc.). Requires paired modified V2board panel.
- Tech stack: Go; key deps include xray-core, cobra, logrus, viper, lego/acme, smux.
- Entry: `main.go` wires cobra commands in `cmd/` (server/version subcommands) and core setup.
- Layout (top-level): `api/`, `cmd/`, `limiter/`, `conf/`, `node/`, `proxy/`, `core/`, `common/`, `script/`, `build_assets/`, `Dockerfile`, `README.md`.
- Certificates/config: SATLS inbound built from panel/node settings; cert paths under `/etc/v2node/` for split links.
- Build artifact: `build_assets/v2node`.