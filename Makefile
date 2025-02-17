build: aarch64-unknown-linux-musl x86_64-unknown-linux-musl

%-unknown-linux-musl:
	repro-env build -- sh -c ' \
	RUSTFLAGS="-C strip=symbols" \
	cargo build --target $@ --release'

.PHONY: build *-unknown-linux-musl
