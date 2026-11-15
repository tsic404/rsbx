# syntax=docker/dockerfile:1

# ---- build ----------------------------------------------------------------
FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/rsbx ./cmd/rsbx \
 && go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/rsbxd ./cmd/rsbxd \
 && go build -trimpath -ldflags="-s -w" -o /out/rsbx-tramp ./cmd/rsbx-tramp \
 && go build -trimpath -ldflags="-s -w" -o /out/rsbx-guard ./cmd/rsbx-guard

# ---- test ----------------------------------------------------------------
# The filesystem tests mount a real FUSE filesystem, so they need the fuse
# helper at run time. Keeping this stage separate means the runtime image does
# not carry a Go toolchain.
FROM build AS test
RUN apk add --no-cache fuse3
ENTRYPOINT ["go"]
CMD ["test", "./..."]

# ---- runtime --------------------------------------------------------------
# A sandbox needs bubblewrap (the view), fuse3 (the mount) and the agent
# toolchain the configuration allows to run locally.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bubblewrap fuse3 ca-certificates \
      coreutils findutils grep sed gawk tar diffutils \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/ /usr/local/bin/
COPY config.example.toml /etc/rsbx/config.toml

# The client looks for the trampoline and the guard next to itself.
ENV PATH=/usr/local/bin:$PATH

RUN useradd --create-home --uid 1000 --shell /bin/bash rsbx
USER rsbx
WORKDIR /home/rsbx

# Both ends ship in one image. The default action is the client, which needs
# /dev/fuse and an unprivileged user namespace:
#
#   docker run --rm -it --privileged -v /dev/fuse \
#     -v /srv/tree:/work -v ~/.codex:/home/rsbx/.codex rsbx
#
# To serve a remote tree instead, override the entry point:
#
#   docker run --rm --entrypoint rsbxd -v /srv/tree:/tree rsbx \
#     -socket /run/rsbx/daemon.sock -root /tree
ENTRYPOINT ["rsbx"]
CMD ["-config", "/etc/rsbx/config.toml"]
