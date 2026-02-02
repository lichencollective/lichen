FROM registry.suse.com/bci/rust:1.92 as build

RUN zypper -n in libopenssl-3-devel

WORKDIR /app

COPY . .
RUN cargo build --release --package server --bin server

FROM registry.suse.com/bci/bci-base:latest

WORKDIR /app

COPY --from=build /app/target/release/server /usr/local/bin/server

CMD ["/usr/local/bin/lichen", "run"]
