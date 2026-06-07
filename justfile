set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := true

generate:
  go generate ./...

test:
  go test ./... -count=1

# daemon:
#   go generate ./...
#   go build
#   sudo ./ebpf-test -mark-name firefox
#
# watcher:
#   sudo ./ebpf-test -watcher
