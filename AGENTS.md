# AGENTS.md

Agent-specific guidance for Bitcredit-Core. See [README.md](README.md) for the project overview
and the organisation's [contributing guide](https://github.com/BitcreditProtocol/.github/blob/master/CONTRIBUTING.md)
for shared contribution rules.

Working preferences are defaults; the compatibility requirements below are mandatory.
If a task conflicts with them, surface the conflict.

Be terse. Make the smallest change that fully solves the task. Avoid unrelated refactoring
and documentation.

## Project Map

Dependencies run `bcr-ebill-core` → `bcr-ebill-persistence` → `bcr-ebill-api` →
`bcr-ebill-transport` → `bcr-ebill-flutter-ffi`; the supported consumer entrypoint is the
Flutter plugin `ebill_flutter_ffi`. The FFI crate builds native `cdylib`/`staticlib` artifacts
for Flutter. There is no server: keys and state live on the client, persisted through
SurrealDB/SurrealKV at app-provided database paths, while Nostr relays, Esplora, mints and
other configured services are external. Workspace crates are libraries; no crate defines a
binary.

## Quality Gates

Full gate before every PR; the workspace suite is one command:

```
just check     # Flutter/Dart codegen, fmt --check, cargo check, cargo test --all,
               # clippy --all-targets --all-features -D warnings, cargo deny check
just flutter   # regenerate Dart/flutter_rust_bridge bindings only
```

Needs Flutter, `flutter_rust_bridge_codegen` and `cargo-deny` on PATH
([docs/flutter.md](docs/flutter.md) covers Flutter/FFI setup).
CI does not use `just`: `Rust CI` fails on fmt, deny and clippy errors, but runs clippy without
`--all-targets -D warnings`, and `Test coverage` runs `cargo test --workspace`, so a green CI
does not prove clippy warnings are clean — `just check` is where they are enforced, and the PR
checklist asks for both.

* Tests run natively. The Flutter FFI layer gets basic wiring coverage and is excluded from
  Rust coverage; put behavior tests in the lower crates whenever possible.
* Keep tests hermetic: in-memory SurrealDB (`kv-mem`), `mockall`, `mockito` and the
  in-process `nostr-relay-builder` relay are the fixtures; CI has no live relay, Esplora or mint.
* NEVER manually trigger the `Release precompiled binaries` workflow to test anything: it
  publishes signed precompiled native artifacts to GitHub releases. Validate locally with
  `just check`; release workflows are not test fixtures.

## Key Patterns

* **Native Flutter is the supported SDK boundary.** `bcr-ebill-flutter-ffi` is the
  consumer-facing Rust crate and uses `flutter_rust_bridge`/Cargokit to expose the SDK to
  Flutter. `ServiceTraitBounds` is `Send + Sync`; do not add wasm32- or browser-specific
  compatibility code unless the project explicitly restores that target.
* **`protocol/` types are the wire format.** Blocks are borsh-serialised, hashed and
  Schnorr-signed, so a field change alters hashes other clients already verify. Chains are
  append-only (`Blockchain::try_add_block`, no removal) and every inbound block is re-validated
  locally: relays are transport, not consensus (CHANGELOG 0.5.1-1 still calls chain reordering
  a pre-mainnet placeholder). Backwards compatibility of wire formats and persisted data is
  mandatory. Never introduce changes that break existing clients or stored data.
* **Bill, mint and payment states are separate machines.** `BillState` in `application/bill`,
  `MintRequestStatus` in `protocol/mint` and Esplora payment checks
  (`bcr-ebill-api/src/external/bitcoin.rs`) are computed independently. A valid signature
  proves who signed, not that a bill is paid or a mint solvent; `Accepted`/`MintingEnabled`
  mean the mint agreed, and `MintOffer.proofs` is separately optional.
* **The Flutter FFI/Dart boundary is a public API.** Rust bridge sources live under
  `crates/bcr-ebill-flutter-ffi/src/ffi/`; generated bridge output lives under
  `lib/src/rust/` and in `crates/bcr-ebill-flutter-ffi/src/frb_generated.rs`. Never hand-edit
  generated bridge code — change its source and run `just flutter`. Signature, type and data
  shape changes affect Flutter consumers and must be treated as public API changes.
* **Dependencies float.** `Cargo.lock` is gitignored, so CI resolves fresh within `Cargo.toml`
  ranges — don't commit one. `bcr-common` is pinned by git `rev` in the root `Cargo.toml` and
  bumped there (deny.toml allows git sources only from the BitcreditProtocol org).

## Common Gotchas

1. **Generated Flutter bridge code is checked in.** Edit the Rust FFI sources or hand-written
   Dart API, then run `just flutter`; do not patch `lib/src/rust/` or
   `crates/bcr-ebill-flutter-ffi/src/frb_generated.rs` by hand.

This list grows from real incidents only — add one whenever an agent or human loses time
here; it is the cheapest productivity investment in the repo.

## Glossary

Names that look alike belong to separate machines (Key Patterns); never join them.

* **`BillAcceptState::Accepted`** — an `Accept` block proves the drawee assented, not that anyone paid.
* **`BillPaymentState::Paid`** — Esplora confirmed the funds; every lesser state is unpaid.
* **`QuoteStatusReply::Accepted`** / **`MintRequestStatus::Accepted`** — the mint (remote) or
  this client (stored) recorded offer assent; minting is not yet allowed.
* **`MintingEnabled`** — the mint permits issuance; `MintOffer.proofs` may still be absent.
* **signed** — a verified block authenticates its signer, nothing about business state.

## Plans and work artifacts

* Plans, research notes and scratch files stay outside the worktree or in the gitignored
  `docs/plans/`; working state is not product documentation.
* The merged PR plus its CHANGELOG bullet is the implementation record. Do not add a second
  checklist or PR summary to the repo; it drifts from the code.

## Working Agreements

Organisation-wide rules (branch protection, reviews, labels, Dependabot) live in the
[contributing guide](https://github.com/BitcreditProtocol/.github/blob/master/CONTRIBUTING.md).
This section is the per-task delta.

* Open pull requests against `master`. Branch from it too: basing work on another branch
  conflicts in exactly the files other people are changing.
* Never open, mark ready or merge a PR, and never push a tag, unless the developer
  explicitly asks. Each is visible to the whole team, and a tag also starts a release.
* Commit small and often. Each commit is self-contained, passes the gate above and is
  reviewable on its own; the subject says why, not just what. Reviewers only catch
  mistakes in changes they can hold in their head.
* Titles: conventional-commit style in plain language, e.g. `fix(api): recourse blocks
  reach the drawee again`. Release notes are built from labels (see
  [`.github/release.yml`](.github/release.yml)), so label `bug`, `enhancement`,
  `documentation` or `dependencies`.
* Body: the problem in a sentence or two, then how it was fixed, then how it was verified.
  The [PR template](.github/PULL_REQUEST_TEMPLATE.md) asks exactly that. End with the
  model and harness that did the work.
* Evidence: the test that failed before and passes now, or for a wire or public API
  change, the consumer that was rebuilt against it. Upload evidence to the PR on GitHub;
  never commit PR-only screenshots or assets.
* One concern per PR. If the description needs an "also", split it.
* Babysitting a PR: poll checks and comments newer than the last push; verify each bot
  finding against the source, fix the real ones, dismiss false positives with a written
  reason. No status check is required to merge, so a red check may predate your change:
  confirm that before blaming it, and say so in the PR. Stay quiet when nothing is new;
  stop when checks are green on the latest commit.
* Every PR adds a bullet to the top section of [CHANGELOG.md](CHANGELOG.md). Describe
  public API changes in the PR and changelog. The version is bumped once per
  cycle in the root `[workspace.package]` (`init X.Y.Z` commits), never per PR; scheme in
  [docs/versioning.md](docs/versioning.md).
* Workflows pin actions by commit SHA with a version comment (#982); keep that form.
  Tagged releases publish signed Flutter precompiled binaries via
  [`.github/workflows/cd_precompiled.yml`](.github/workflows/cd_precompiled.yml); see
  [docs/flutter.md](docs/flutter.md) for how consumers use them.

## See Also

* [docs/index.md](docs/index.md) — documentation hub
* [docs/concepts.md](docs/concepts.md) — bill actions and states by role; read before touching bill logic
* [docs/flutter.md](docs/flutter.md) — Flutter/FFI prerequisites, binding generation, package use and precompiled binaries
* [docs/testing.md](docs/testing.md) — which layer gets which kind of test
* [.github/copilot-instructions.md](.github/copilot-instructions.md) — Copilot adapter with a longer architecture tour; check it for drift when gates change here
