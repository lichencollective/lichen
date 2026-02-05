FROM registry.suse.com/bci/bci-base:latest

ARG BUILD_DIR="target/debug"

RUN mkdir -p /app
COPY ${BUILD_DIR}/lichen /usr/local/bin/lichen
WORKDIR /app

EXPOSE 3000

CMD ["/usr/local/bin/lichen", "run"]
