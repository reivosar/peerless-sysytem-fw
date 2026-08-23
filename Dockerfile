FROM rust:1.91-bookworm AS development

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        libssl-dev \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy \
    && rustup target add wasm32-unknown-unknown \
    && toolchain_bin="$(rustc --print sysroot)/bin" \
    && ln -sf "$toolchain_bin/cargo" /usr/local/bin/cargo \
    && ln -sf "$toolchain_bin/rustc" /usr/local/bin/rustc \
    && ln -sf "$toolchain_bin/rustdoc" /usr/local/bin/rustdoc \
    && ln -sf "$toolchain_bin/rustfmt" /usr/local/bin/rustfmt \
    && ln -sf "$toolchain_bin/cargo-fmt" /usr/local/bin/cargo-fmt \
    && ln -sf "$toolchain_bin/clippy-driver" /usr/local/bin/clippy-driver \
    && ln -sf "$toolchain_bin/cargo-clippy" /usr/local/bin/cargo-clippy

WORKDIR /workspace
ENV CARGO_HOME=/cargo
ENV CARGO_TARGET_DIR=/target

CMD ["cargo", "test", "--workspace"]
