# Contributing to cosmos-bsn-contracts

This document outlines expectations and best practices to help keep contributions — issues, pull requests, and discussions — clear, consistent, and collaborative.

## Code Style

When choosing between clever or obvious code, always prefer the obvious. Prioritize readability and maintainability.

We adhere to idiomatic Rust code style, with project-specific refinements configured in `rustfmt.toml`. All Clippy lints must pass — suppressions should be rare and well-justified. Every commit must successfully run `cargo +nightly fmt --all` and produce zero Clippy warnings across all code: libraries, binaries, examples, and tests.

Imports (`use` statements) should be grouped together in a single block at the top of each file. Avoid scattering them across functions or placing them mid-file unless there's a compelling reason (e.g., feature gating).

Write idiomatic Rust to minimize the need for `.unwrap()`. Using `unwrap()` is strictly forbidden for the contract code running in the blockchain context. Use `.expect()` only when you can convince reviewers that it will never panic, or when panicking is an explicitly justified behavior. The correctness of `.expect()` should be evident from the local context (for standalone functions) or from data structure invariants (for internal methods). If correctness cannot be guaranteed, use `Result<T, E>` instead.  

Avoid comments that restate what’s already obvious from the code.

```Rust
// ❌ Redundant:
/// bsn_id is the unique ID of the BSN chain.
pub bsn_id: String;

// ✅ Better:
/// The unique ID of the BSN chain.
pub bsn_id: String;
```

If code is incomplete or has known issues, include a `TODO` comment explaining what remains to be done or what is not handled properly. For significant issues, consider opening a GitHub issue.

Prefer longer, descriptive variable names. Short variable names (1-3 characters) are typically discouraged, except in specific cases like `id` for entity data structures or `i` for simple loops. However, for test code, shorter variable names are acceptable if they improve readability and maintainability.

When in doubt, mimic the style you see in the existing codebase. Consistency trumps perfection.

## Code of Conduct

All contributors are expected to maintain a respectful and professional attitude toward each other.
