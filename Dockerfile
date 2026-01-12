FROM --platform=linux/amd64 messense/rust-musl-cross:x86_64-musl AS amd64-chef
RUN cargo install cargo-chef && \
    curl -sSL https://github.com/upx/upx/releases/download/v5.1.0/upx-5.1.0-amd64_linux.tar.xz | tar -xJ && \
    mv upx-*/upx /usr/local/bin/
WORKDIR /app

FROM --platform=linux/arm64 messense/rust-musl-cross:aarch64-musl AS arm64-chef
RUN cargo install cargo-chef && \
    curl -sSL https://github.com/upx/upx/releases/download/v5.1.0/upx-5.1.0-arm64_linux.tar.xz | tar -xJ && \
    mv upx-*/upx /usr/local/bin/
WORKDIR /app

FROM ${TARGETARCH}-chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM ${TARGETARCH}-chef AS builder
ARG TARGETARCH
ARG BINARY_NAME=oidc-forward-auth-middleware

COPY --from=planner /app/recipe.json recipe.json
RUN TARGET=$(echo ${TARGETARCH} | sed 's/arm64/aarch64/;s/amd64/x86_64/') && \
    cargo chef cook --release --target ${TARGET}-unknown-linux-musl --recipe-path recipe.json

COPY . .
RUN TARGET=$(echo ${TARGETARCH} | sed 's/arm64/aarch64/;s/amd64/x86_64/') && \
    cargo build --release --target ${TARGET}-unknown-linux-musl --bin ${BINARY_NAME} && \
    mv ./target/${TARGET}-unknown-linux-musl/release/${BINARY_NAME} /build && \
    upx --best --lzma /build

FROM scratch AS runtime
COPY --from=builder /build /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
USER 1000:1000
EXPOSE 3000
ENTRYPOINT ["/app"]
