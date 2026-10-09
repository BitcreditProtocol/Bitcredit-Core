# Flutter FFI Setup

## Prerequisites

Make sure you have all [prerequisites](./prerequisites.md) installed.

* Install Rust
* Install Flutter
* Install [just](https://github.com/casey/just)
* `cargo install flutter_rust_bridge_codegen`

## Generate bindings

```bash
just flutter
```

## Import this package

This package can be imported as follows:

In `pubspec.yaml`:

```yaml
   ebill_flutter_ffi:
     git:
       url: git@github.com:BitcreditProtocol/Bitcredit-Core.git
       ref: vx.x.x
```

The `ref` can either be a commit hash, a branch or a tag.

### Precompiled binaries

This package publishes signed precompiled Rust binaries for iOS, Android, macOS,
Windows and Linux (x64 and arm64; Linux needs glibc 2.39 or newer) from
`.github/workflows/cd_precompiled.yml`. App CI can opt in by adding
`cargokit_options.yaml` at the Flutter app root:

```yaml
use_precompiled_binaries: true
```

Alternatively set `CARGOKIT_USE_PRECOMPILED_BINARIES=true` in the app build
environment. Cargokit falls back to a local Rust build if a signed binary for
the current crate hash and target is not available.

The binaries are built when a `v*` tag is pushed and published as a
`precompiled_<crate hash>` prerelease of this repository. Pin the dependency
`ref` to a release tag to use them; most branch commits have no matching
binaries and build locally.

Check the test harness project in the `./example/` folder for how to use this library in Flutter.
