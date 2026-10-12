# syntax=docker/dockerfile:1
#
# kc-relay image. The build context is the repository root:
#
#   docker build -f deploy/docker/Dockerfile -t kc-relay:local .
#
# It builds natively for the machine running the build (arm64 and amd64 both
# work). Only the kc-relay binary ends up in the runtime image.

ARG RUST_VERSION=1.99
ARG DEBIAN_SUITE=trixie

FROM rust:${RUST_VERSION}-slim-${DEBIAN_SUITE} AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,id=kc-relay-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=kc-relay-target,target=/src/target,sharing=locked \
    cargo build --release --locked -p kc-relay \
 && install -D -m 0755 target/release/kc-relay /out/kc-relay

FROM debian:${DEBIAN_SUITE}-slim
RUN groupadd --system --gid 10001 kc \
 && useradd --system --uid 10001 --gid kc --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin kc \
 && install -d -o 10001 -g 10001 -m 0700 /data
COPY --from=build /out/kc-relay /usr/local/bin/kc-relay
USER 10001:10001
ENV KC_RELAY_BIND=0.0.0.0:8080 \
    KC_RELAY_DB=/data/relay.db \
    RUST_LOG=info
VOLUME ["/data"]
EXPOSE 8080
STOPSIGNAL SIGTERM
# The image has no curl; the binary probes its own /healthz.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/kc-relay", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/kc-relay"]
# Which commit this image was built from (set by the deploy, last so it
# doesn't invalidate the layers above).
ARG KC_REVISION=unknown
LABEL org.opencontainers.image.revision=${KC_REVISION}
