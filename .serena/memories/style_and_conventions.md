## Style and Conventions
- Language: Go 1.25 (toolchain go1.25.0); standard Go module layout.
- Formatting: gofmt; keep imports grouped by standard library/external.
- Logging: uses logrus in several packages; follow existing patterns.
- CLI: built with cobra under `cmd/`; version injected via ldflags `cmd.version`.
- TLS/SATLS proxy code prefers lowercase/trimmed server names; avoid introducing non-ASCII identifiers.