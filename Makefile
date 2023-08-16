.PHONY: build
build:
	cargo build --release

.PHONY: format
format:
	cargo +nightly fmt