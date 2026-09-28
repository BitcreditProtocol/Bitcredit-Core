# E-Bills

Bitcredit E-Bills project

### Crates

The project consists of the following crates:

* `bcr-ebill-core` - core data models and traits
* `bcr-ebill-persistence` - persistence traits and SurrealDB implementation
* `bcr-ebill-transport` - network transport API traits and Nostr implementation
* `bcr-ebill-api` - API of the E-Bills project, contains most of the business logic
* `bcr-ebill-flutter-ffi` - Entrypoint for the Native Flutter FFI version of the E-Bill API

### Entrypoint

There is a `Native Flutter FFI` entry point into the API. You can find the documentation to build and configure it [here](docs/index.md):

#### Run locally

Check the prerequisites generally [here](./docs/prerequisites.md) and for flutter [here](./docs/flutter.md).

In the project root, to re-build the bindings:

```
just flutter
```

then (you can replace linux with macos etc.)

```
cd example
flutter run -d linux
```

If you want to run a second version, you can simply, from another tab, run:

```
cd example
EBILL_HARNESS_DIR=/tmp/some-other-folder flutter run -d linux
```

and it will start a second app, with it's state set to the folder you set to.

Deleting this folder resets the state.

### Tests

You can run the existing tests using the following commands in the project root:

```bash
// without logs
cargo test

// with logs - (env_logger needs to be activated in the test to show logs)
RUST_LOG=info cargo test -- --nocapture
```

## Contribute

Check out the organisation's [contributing guide](https://github.com/BitcreditProtocol/.github/blob/master/CONTRIBUTING.md).

