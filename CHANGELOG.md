# Changelog

All notable changes to `hermes-iroh-interconnect` are documented here.

## [0.3.1] - 2026-09-21

This point release hardens the v0.3 transport and file-transfer paths without
changing the public tool surface or the CI integration-test policy.

### Added

- Per-peer shared-secret authentication for task traffic. Outbound calls now
  carry the secret learned during pairing, and inbound tasks are rejected before
  Hermes dispatch when the secret is missing or incorrect.
- Post-receive file-tree validation that rejects symlinks and paths resolving
  outside the requested destination directory.
- Regression coverage for invalid peer secrets and received symlink escapes.

### Changed

- Plugin registration now fails loudly when client tools or the inbound adapter
  cannot register, instead of leaving a partially enabled plugin hidden behind
  a warning.
- Pairing documentation now accurately describes `confirm=true` as an
  application-level confirmation argument. A dedicated desktop/operator
  approval prompt remains future work.
- Task-envelope and sidecar client tests now exercise authenticated calls.

### Deferred

- Automatic cleanup of long-lived `send_hermes` providers after failed
  automatic delivery remains a future enhancement.
- The Hermes integration suite remains manual-only by design and was not moved
  into the normal CI job.

### Verification

- Python: `67 passed, 3 skipped` (the skipped tests are optional Hermes-source
  integration tests).
- Rust: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo test` pass.

[0.3.1]: https://github.com/rahlquist/hermes-iroh-interconnect/compare/v0.3.0...v0.3.1
