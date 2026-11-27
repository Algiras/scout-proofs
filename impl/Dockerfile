# SPDX-License-Identifier: Apache-2.0
FROM rust:alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY scout-core scout-core
COPY scout-wire scout-wire
COPY scout-broker scout-broker
COPY scout-runner scout-runner
COPY scout-mockprovider scout-mockprovider
COPY scout-attacker scout-attacker
RUN cargo build --release --locked --bins \
 && mkdir -p /out/usr/local/bin /out/data /out/shared \
 && cp target/release/scoutd target/release/mockprovider target/release/scout-run target/release/scout-whoami target/release/scout-attacker target/release/scout-victim /out/usr/local/bin/

# Static binaries on an empty image, running as an unprivileged user.
FROM scratch
COPY --from=build --chown=65532:65532 /out/ /
USER 65532:65532
WORKDIR /data
EXPOSE 8080 9000
ENTRYPOINT ["/usr/local/bin/scoutd"]
