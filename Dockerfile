# syntax=docker/dockerfile:1
ARG UBUNTU_RELEASE=latest
FROM ubuntu:${UBUNTU_RELEASE} AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    fuse3 \
    libfuse3-dev \
    bzip2 \
    libbz2-dev \
    zlib1g-dev \
    libattr1-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DUSE_FUSE3=ON \
    && cmake --build build -j"$(nproc)" \
    && cmake --install build --prefix /usr/local

FROM ubuntu:${UBUNTU_RELEASE}
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    fuse3 \
    libfuse3-3 \
    libfuse3-4 \
    libbz2-1.0 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/* || \
    (apt-get update && apt-get install -y --no-install-recommends \
    fuse3 \
    libbz2-1.0 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*)

COPY --from=builder /usr/local/bin/apfs-fuse /usr/local/bin/apfs-fuse
COPY --from=builder /usr/local/bin/apfsutil /usr/local/bin/apfsutil
COPY --from=builder /usr/local/bin/apfs-dump /usr/local/bin/apfs-dump
COPY --from=builder /usr/local/bin/apfs-dump-quick /usr/local/bin/apfs-dump-quick

ENTRYPOINT ["/usr/local/bin/apfs-fuse"]
