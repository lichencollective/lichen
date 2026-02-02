default: build

build: build_binary

build_binary:
    cargo build

build_container:
    ./scripts/build.sh

publish_container:
    ./scripts/publish.sh

lint:
    cargo lint

test:
	cargo test
