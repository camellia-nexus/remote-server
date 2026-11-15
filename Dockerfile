# syntax=docker/dockerfile:1.24.0@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM rust:1.99.1-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8 AS builder

WORKDIR /build
COPY . .
RUN cargo build --locked --release --bins \
    && install -Dm0755 target/release/camellia-remote-identity /out/camellia-remote-identity \
    && install -Dm0755 target/release/camellia-remote-relay /out/camellia-remote-relay \
    && install -Dm0755 target/release/camellia-remote-utils /out/camellia-remote-utils

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

ARG VERSION
ARG REVISION
ARG SOURCE_URL
RUN test -n "$VERSION" \
    && test -n "$REVISION" \
    && test -n "$SOURCE_URL"
LABEL org.opencontainers.image.title="Camellia Remote Server" \
      org.opencontainers.image.description="Identity, rendezvous and relay services for Camellia Remote" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.source="$SOURCE_URL" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.vendor="Camellia Computing"

RUN groupadd --gid 10001 camellia \
    && useradd --uid 10001 --gid camellia --home-dir /var/lib/camellia-remote \
      --create-home --shell /usr/sbin/nologin camellia \
    && chmod 0700 /var/lib/camellia-remote

COPY --from=builder /out/ /usr/local/bin/
COPY LICENSE NOTICE SOURCE_PROVENANCE.json /usr/local/share/doc/camellia-remote/

USER 10001:10001
WORKDIR /var/lib/camellia-remote
ENV HOME=/var/lib/camellia-remote

EXPOSE 21115/tcp 21116/tcp 21116/udp 21117/tcp 21118/tcp 21119/tcp
VOLUME ["/var/lib/camellia-remote"]

CMD ["camellia-remote-identity"]
