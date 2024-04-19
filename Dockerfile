FROM lukemathwalker/cargo-chef:latest-rust-alpine AS chef
WORKDIR /app

FROM chef AS planner
COPY Cargo* .
COPY src src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apk add openssl-dev
ENV OPENSSL_DIR=/usr
COPY --from=planner /app/recipe.json .
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN rustup target add aarch64-unknown-linux-musl
RUN cargo build --release --target aarch64-unknown-linux-musl

FROM scratch AS runtime
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/oidc-forward-auth-middleware /usr/local/bin/app
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/app"]