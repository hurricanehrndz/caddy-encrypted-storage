# update go get -tool -modfile=tools.mod github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
.PHONY: lint
lint:
	@pre-commit run --all-files

.PHONY: format
format:
	@go tool -modfile=tools.mod golangci-lint fmt

.PHONY: test
test:
	go test -v -race  -covermode=atomic ./...

caddy: build/darwin/caddy
build/darwin/caddy:
	test -d $(@D) || mkdir -p $(@D)
	CGO_ENABLED=1 go tool -modfile=tools.mod xcaddy build \
		--output $(@) \
		--with github.com/mohammed90/caddy-encrypted-storage=.

# Build with team ID for macOS keychain ACL (replace SBSSF9BESA with your Apple Team ID)
caddy-signed: build/darwin/caddy-signed
build/darwin/caddy-signed:
	test -d $(@D) || mkdir -p $(@D)
	CGO_ENABLED=1 go tool -modfile=tools.mod xcaddy build \
		--output $(@) \
		--with github.com/mohammed90/caddy-encrypted-storage=. \
		-- -ldflags "-X github.com/mohammed90/caddy-encrypted-storage/internal/credstore.buildTimeTeamID=SBSSF9BESA"

.PHONY: install-hooks
install-hooks:
	@pre-commit install --install-hooks
