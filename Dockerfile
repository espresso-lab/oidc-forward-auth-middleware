FROM lukemathwalker/cargo-chef:latest-rust-alpine AS chef
WORKDIR /app

FROM chef AS planner
COPY Cargo* .
COPY src src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apk add pkgconfig openssl-dev libc-dev
ENV OPENSSL_DIR=/usr
COPY --from=planner /app/recipe.json .
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release
RUN mv ./target/release/oidc-forward-auth-middleware ./app

FROM scratch AS runtime
WORKDIR /app
COPY --from=builder /app/app /usr/local/bin/
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/app"]