# The production image: one static binary and nothing else. Mozilla's root
# certificates are compiled in, so the image needs no CA files, and the
# renewal loop lives in the binary, so it needs no shell.

# The toolchain rust-toolchain.toml pins. On Alpine the host target is
# x86_64-unknown-linux-musl, which links statically.
FROM rust:1.100.0-alpine3.24 AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN cargo build --release --locked

FROM scratch

COPY --from=builder /src/target/release/acme /acme

# Runs as root, as certbot does: it writes the private keys under
# /etc/letsencrypt, which root owns.
ENTRYPOINT ["/acme"]
CMD ["run"]
