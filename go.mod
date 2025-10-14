module github.com/iudanet/gophkeeper

go 1.25.0

tool (
	golang.org/x/tools/cmd/goimports
	golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment
)

require (
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.43.0
	golang.org/x/term v0.36.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/mod v0.28.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/telemetry v0.0.0-20250908211612-aef8a434d053 // indirect
	golang.org/x/tools v0.37.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
