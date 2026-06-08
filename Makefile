\.PHONY: build dev clean dataset check

build:
	cd crates/parser && wasm-pack build --target web --out-dir ../../web/pkg

dev:
	cd crates/parser && wasm-pack build --target web --out-dir ../../web/pkg --dev

clean:
	cd crates/parser && cargo clean
	rm -rf web/pkg

check:
	cd crates/parser && cargo check

dataset:
	python3 generate-dataset.py
