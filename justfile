set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := true

generate:
  go generate ./...

test:
  go test ./... -count=1

build: generate
  go build -o ./pmark ./cmd

daemon: build
  sudo ./pmark -fwmark -rule-comm firefox

watcher: build
  sudo ./pmark -watcher

help: build
  ./pmark --help

release-check-env:
	@missing=0; \
	for name in GITHUB_TOKEN GPG_FINGERPRINT PACKAGE_MAINTAINER AUR_KEY MYREPO; do \
		if [ -z "${!name:-}" ]; then \
			echo "missing required environment variable: ${name}" >&2; \
			missing=1; \
		fi; \
	done; \
	if [ "${missing}" -ne 0 ]; then \
		exit 1; \
	fi

release-check: release-check-env
	goreleaser check

release-snapshot: release-check-env
	SSH_BIN="${SSH_BIN:-$(command -v ssh)}" goreleaser release --clean --snapshot --skip=publish --skip=validate

release: release-check-env
	SSH_BIN="${SSH_BIN:-$(command -v ssh)}" goreleaser release --clean --skip=validate
	"$MYREPO/maintain" save feat "add yggd $(git describe --tags --abbrev=0)"

