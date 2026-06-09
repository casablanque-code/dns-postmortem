\.PHONY: build dev clean dataset check

build:
	cd crates/parser && wasm-pack build --target web --out-dir ../../web/pkg

dev:
	wrangler pages dev web

clean:
	cd crates/parser && cargo clean
	rm -rf web/pkg

check:
	cd crates/parser && cargo check

dataset:
	python3 generate-dataset.py
