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

### How the native library is built

The package ships its Rust library through a Dart build hook
([`hook/build.dart`](../hook/build.dart), native assets), not as a Flutter
plugin. It has no podspec, Swift package, Gradle or CMake project, so iOS and
macOS apps need neither CocoaPods nor Swift Package Manager for it. Flutter
bundles the library itself, on iOS and macOS as the dynamic framework
`bcr_ebill_flutter_ffi.framework`, which Flutter signs together with the app.
Flutter embeds that framework but does not link it into the app, so call
`RustLib.init()` without an `externalLibrary`; `ExternalLibrary.process()`
finds no symbols there.

Requirements for the consuming app:

* Flutter 3.50 or newer.
* A minimum deployment target of at least iOS 15 and macOS 13. Flutter 3.50
  always builds code assets for iOS 15 and macOS 13, whatever the app declares.
* For local Rust builds: [rustup](https://rustup.rs). The hook builds with the
  exact toolchain and targets pinned in
  `crates/bcr-ebill-flutter-ffi/rust-toolchain.toml`, which rustup installs on
  first use. Android builds also need the Android NDK (r27 or newer).

### Precompiled binaries

This package publishes signed precompiled Rust binaries from
`.github/workflows/cd_precompiled.yml` for exactly these targets:

* Android: `armv7-linux-androideabi`, `aarch64-linux-android`, `x86_64-linux-android`
* iOS: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`
* macOS: `aarch64-apple-darwin`, `x86_64-apple-darwin`
* Linux: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` (glibc 2.39 or newer)
* Windows: `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`

A supported configuration without a usable published binary for the current
crate hash builds locally with cargo. Apps opt in in their `pubspec.yaml`:

```yaml
hooks:
  user_defines:
    ebill_flutter_ffi:
      use_precompiled_binaries: true
```

Without this setting the hook uses precompiled binaries only when rustup is not
installed. Hooks do not see the app's environment variables, so the old
`CARGOKIT_USE_PRECOMPILED_BINARIES` variable and `cargokit_options.yaml` no
longer have any effect.

`dart run <script>` in an app first runs the build hooks for the host
platform, so it downloads the host binary (with the opt-in) or builds the Rust
library locally; `dart run <package>:<executable>`, such as `build_runner`,
runs no hooks.

The hook downloads the binary for the current crate hash and target from the
`precompiled_<crate hash>` release, verifies its signature against the public
key in [`precompiled_binaries.yaml`](../precompiled_binaries.yaml), and builds
locally with Rust if no verified binary is available. Downloads that stall or
fail with a network error, HTTP 429 or 5xx are retried a few times before the
hook falls back to the local build. Binaries are built for Android API 24, iOS
15 and macOS 13. Flutter passes the app's `minSdk` to the hook, so an Android app
with a `minSdk` below 24 builds locally; for iOS and macOS, Flutter always asks
for 15 and 13, so the binaries always match.

The crate hash covers every file in every workspace crate's directory (with its
path), the workspace `Cargo.toml`, `Cargo.lock` and `.cargo/config.toml`,
`rust-toolchain.toml`, `precompiled_binaries.yaml` and those minimum versions,
so any change that can alter the library selects a new release.

The binaries are built when a `v*` tag is pushed and published as a
`precompiled_<crate hash>` prerelease of this repository. Pin the dependency
`ref` to a release tag to use them; most branch commits have no matching
binaries and build locally.

Check the test harness project in the `./example/` folder for how to use this library in Flutter.
