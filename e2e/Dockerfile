# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
	go mod download

COPY . .

ARG E2E_COVERAGE=0
ARG E2E_COVERPKG=github.com/asciimoth/p-mark/...

RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	if [ "$E2E_COVERAGE" = "1" ]; then \
		go build -cover -covermode=atomic -coverpkg="$E2E_COVERPKG" -o /usr/local/bin/pmark ./cmd; \
	else \
		go build -o /usr/local/bin/pmark ./cmd; \
	fi

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

RUN rm -f /etc/apt/apt.conf.d/docker-clean \
	&& printf 'Binary::apt::APT::Keep-Downloaded-Packages "true";\n' >/etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
	--mount=type=cache,target=/var/lib/apt,sharing=locked \
	apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		bash \
		ca-certificates \
		curl \
		jq \
		procps \
		python3 \
		util-linux

COPY --from=build /usr/local/bin/pmark /usr/local/bin/pmark
COPY e2e /e2e

WORKDIR /e2e
ENTRYPOINT ["/e2e/run-case.sh"]

