.PHONY: build
build:
	cargo build --target=wasm32-unknown-unknown --release

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings

.PHONY: e2e-test
e2e-test: build
	bats e2e.bats

.PHONY: test
test: fmt lint
	cargo test

.PHONY: clean
clean:
	cargo clean
