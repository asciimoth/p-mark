# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 go build -o /pmark ./cmd

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

RUN rm -f /etc/apt/apt.conf.d/docker-clean \
	&& printf 'Binary::apt::APT::Keep-Downloaded-Packages "true";\n' >/etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
	--mount=type=cache,target=/var/lib/apt,sharing=locked \
	apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		bash \
		bpftool \
		busybox-static \
		ca-certificates \
		cpio \
		curl \
		iproute2 \
		jq \
		linux-image-amd64 \
		procps \
		python3 \
		util-linux \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=build /pmark /usr/local/bin/pmark
COPY e2e /e2e
COPY e2e/guest/inittab /etc/inittab

# This step only assembles boot files. It cannot load BPF programs or execute
# tests against the container host kernel.
RUN chmod 0755 /e2e/guest/*.sh \
	&& /e2e/guest/build-artifacts.sh

CMD ["/bin/true"]
