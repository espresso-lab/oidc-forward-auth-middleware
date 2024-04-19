# FROM lukemathwalker/cargo-chef:latest-rust-alpine AS chef
# WORKDIR /app

# FROM chef AS planner
# COPY . .
# RUN cargo chef prepare --recipe-path recipe.json

# FROM chef AS builder
# RUN apk add openssl openssl-dev openssl-libs-static pkgconfig
# ENV OPENSSL_DIR=/usr
# COPY --from=planner /app/recipe.json .
# RUN cargo chef cook --release --recipe-path recipe.json
# COPY . .
# RUN cargo build --release --bin oidc-forward-auth-middleware

FROM rust:1-bookworm  AS builder
WORKDIR /app
COPY . .
RUN apt-get install pkg-config libssl-dev
RUN cargo build --release --bin main


FROM debian:bookworm AS runtime
COPY --from=builder /app/target/release/main /app
EXPOSE 3000
ENTRYPOINT ["/app"]
