.PHONY: help test test-ruby test-rust check-shell fmt lint package

help:
	@printf '%s\n' 'make test-ruby    Run Ruby unit and security tests' \
	                'make test-rust    Run Rust format, lint, and tests' \
	                'make check-shell  Validate POSIX shell syntax' \
	                'make test         Run every available test suite' \
	                'make package      Create source ZIP and SHA-256 checksum'

test-ruby:
	ruby -Ipublic/ruby -e 'Dir["public/ruby/test/test_*.rb"].sort.each { |file| require_relative file }'

test-rust:
	cd public/rust && cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test

check-shell:
	sh scripts/check-shell.sh

test: test-ruby check-shell test-rust

fmt:
	cd public/rust && cargo fmt

lint:
	cd public/rust && cargo clippy --all-targets --all-features -- -D warnings

package:
	./scripts/package-source.sh
