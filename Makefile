.PHONY: build
build:
	cargo build --target=wasm32-unknown-unknown --release

annotated-policy.wasm: build
	kwctl annotate -m metadata.yml -o annotated-policy.wasm target/wasm32-unknown-unknown/release/user_group_psp.wasm

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings

.PHONY: e2e-tests
e2e-tests: annotated-policy.wasm
	bats e2e.bats

.PHONY: test
test: fmt lint
	cargo test

.PHONY: clean
clean:
	cargo clean
