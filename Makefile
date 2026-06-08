.PHONY: build dev clean check dataset

build:
	wasm-pack build crates/parser --target web --out-dir ../../web/pkg

dev:
	wrangler pages dev web

clean:
	rm -rf web/pkg crates/parser/target

check:
	cargo check --manifest-path crates/parser/Cargo.toml
	cargo test --manifest-path crates/parser/Cargo.toml

dataset:
	python3 dataset/generate-dataset.py
