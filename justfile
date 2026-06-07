set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := true

generate:
  go generate ./...

test:
  go test ./... -count=1

build: generate
  go build -o ./pmark ./cmd

daemon: build
  sudo ./pmark -mark-name firefox

watcher: build
  sudo ./pmark -watcher
