# syntax=docker/dockerfile:1.4

FROM rust:1-alpine3.17 as build
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN --mount=type=cache,target=/var/cache/apk ln -vs /var/cache/apk /etc/apk/cache && \
    apk add clang-dev musl-dev nettle-dev zstd-dev && \
    rm /etc/apk/cache
WORKDIR /app
COPY ./ /app
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/apt-swarm .
RUN strip apt-swarm

# this is temporary until crane becomes available in the next alpine release
FROM golang:alpine3.17 as crane
RUN go install github.com/google/go-containerregistry/cmd/crane@latest

FROM alpine:3.17
# install dependencies
RUN --mount=type=cache,target=/var/cache/apk ln -vs /var/cache/apk /etc/apk/cache && \
    apk add clang-libs libgcc nettle zstd-libs && \
    rm /etc/apk/cache && \
    mkdir /data
COPY --from=crane /go/bin/crane /usr/bin
# copy the binary
COPY --from=0 /app/apt-swarm /usr/bin
COPY contrib/apt-swarm.conf /etc
ARG UPDATE_CHECK_COMMIT=
ENV UPDATE_CHECK_COMMIT=$UPDATE_CHECK_COMMIT
ENV APT_SWARM_DATA_PATH=/data
ENTRYPOINT ["apt-swarm"]
