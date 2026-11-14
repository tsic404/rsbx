# syntax=docker/dockerfile:1

# ---- build ----------------------------------------------------------------
# All four binaries are static, so the runtime image needs no Go toolchain and
# nothing from the builder besides the four files.
FROM golang:1.24-alpine AS build

WORKDIR /src

# Dependencies first: this layer is cached until go.mod or go.sum changes.
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

# ---- runtime --------------------------------------------------------------
FROM debian:stable-slim

# bubblewrap builds the sandbox view on both ends; fuse3 provides the helper
# that mounts the sandbox root. Both are needed at run time, not to build.
RUN apt-get update \
 && apt-get install -y --no-install-recommends bubblewrap fuse3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# The sandbox needs an unprivileged user namespace, a FUSE device and a mount
# namespace. A container run with --privileged or with the right caps plus
# --device /dev/fuse works; plain docker run of this image will not.
COPY --from=build /out/ /usr/local/bin/
COPY config.example.toml /etc/rsbx/config.toml

# The trampoline, guard and client must sit in one directory: the client looks
# for its helpers next to itself.
ENV PATH=/usr/local/bin:$PATH

# A session needs a writable home for the mount point and the session cookie.
RUN useradd --create-home --uid 1000 rsbx
USER rsbx
WORKDIR /home/rsbx

# The image carries both ends of the sandbox. The default action is the client,
# which needs a FUSE device and an unprivileged user namespace:
#
#   docker run --rm -it --privileged -v /dev/fuse rsbx
#
# To serve a remote tree instead, override the entry point with the daemon:
#
#   docker run --rm -v /srv/tree:/tree --entrypoint rsbxd rsbx \
#     -socket /run/rsbx.sock -root /tree
ENTRYPOINT ["rsbx"]
CMD ["-config", "/etc/rsbx/config.toml"]
