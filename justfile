set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

# The SurrealDB store's tests run an in-memory database, which brings aws-lc;
# its prebuilt objects spare a NASM install on Windows.
export AWS_LC_SYS_PREBUILT_NASM := "1"

default:
    @just --list

setup:
    lefthook install

format:
    cargo fmt --all

format-check:
    cargo fmt --all -- --check

# Every feature on its own, so a feature that only builds because another one
# is on fails here, and the client features for the browser too.
check:
    cargo check
    cargo check --features apple-jws
    cargo check --features native
    cargo check --features license
    cargo check --features server
    cargo check --features stripe
    cargo check --features app-store
    cargo check --features play
    cargo check --features license-server
    cargo check --features surreal
    cargo check --features standalone --bins
    cargo check --all-features
    cargo check --target wasm32-unknown-unknown
    cargo check --target wasm32-unknown-unknown --features apple-jws
    cargo check --target wasm32-unknown-unknown --features license

lint:
    cargo clippy --all-targets --no-deps --all-features

lint-strict:
    cargo clippy --all-targets --no-deps --all-features -- -D warnings
    cargo clippy --no-deps -- -D warnings
    cargo clippy --no-deps --features native -- -D warnings
    cargo clippy --no-deps --features license -- -D warnings
    cargo clippy --all-targets --no-deps --features server -- -D warnings
    cargo clippy --all-targets --no-deps --features play -- -D warnings
    cargo clippy --all-targets --no-deps --features app-store -- -D warnings
    cargo clippy --all-targets --no-deps --features stripe -- -D warnings
    cargo clippy --all-targets --no-deps --features license-server -- -D warnings
    cargo clippy --all-targets --no-deps --features standalone -- -D warnings
    cargo clippy --no-deps --target wasm32-unknown-unknown --features apple-jws -- -D warnings

test:
    cargo nextest run --all-features --no-tests pass
    cargo nextest run --lib --no-tests pass
    cargo test --doc --all-features

spell:
    typos

security:
    cargo deny check

pre-push: format-check check lint-strict test spell

quality: pre-push

package-check:
    cargo package --allow-dirty --list

ci: quality security package-check

package:
    cargo package

# Readability rules inside RSX, checked without rewriting source.
style-check:
    node scripts/rust-style.mjs

style-report:
    node scripts/rust-style.mjs --report

style-test:
    node --test scripts/rust-style.test.mjs

# The g3-payments-server image, from the working tree's committed HEAD.
image tag="g3-payments-server:dev":
    git archive --format=tar HEAD | docker build -t {{tag}} -
