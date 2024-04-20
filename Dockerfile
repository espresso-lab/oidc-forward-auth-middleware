FROM clux/muslrust:stable AS chef
USER root
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ENV RUSTFLAGS='-C target-feature=-crt-static'
ARG TARGETARCH
COPY --from=planner /app/recipe.json recipe.json
COPY platform.sh .
RUN chmod +x platform.sh
RUN ./platform.sh
RUN cargo chef cook --release --target $(cat /.platform) --recipe-path recipe.json
COPY . .
RUN cargo build --release --target $(cat /.platform) --bin main
RUN mv ./target/$(cat /.platform)/release/main ./main

FROM scratch AS runtime
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /app/main /app
EXPOSE 3000
CMD ["/app"]