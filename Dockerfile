# Statically linked against musl so the runtime image can be `scratch`: no
# shell, no package manager, no libc — nothing for an attacker who lands inside
# the container to pivot with, and nothing to patch on a CVE treadmill.
FROM rust:1.97-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

# Dependencies first, so editing src/ does not re-download the world.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo build --release --locked && \
    rm -rf src

COPY src ./src
COPY tests ./tests
# Touch so cargo notices the real sources replaced the stubs.
RUN touch src/main.rs src/lib.rs && \
    cargo build --release --locked && \
    strip target/release/unifi-voucher-proxy


FROM scratch

COPY --from=builder /build/target/release/unifi-voucher-proxy /usr/local/bin/unifi-voucher-proxy

# 65532 is the conventional "nonroot" uid. No /etc/passwd is needed for a
# numeric user, and the binary never writes to disk.
USER 65532:65532

EXPOSE 8080

# The image has no shell, so the binary probes itself.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/unifi-voucher-proxy", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/unifi-voucher-proxy"]
CMD ["serve", "--config", "/etc/unifi-voucher-proxy/config.toml"]
