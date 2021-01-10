FROM rust:latest

WORKDIR /usr/src/confine
COPY . .

# build for release and install
RUN cargo build --release
RUN cargo install --path .

CMD ["/usr/local/cargo/bin/confine"]
