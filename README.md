# E-Bills

Core for Bitcredit E-Bills project.

### Crates

The project consists of the following crates:

* `bcr-ebill-core` - core data models and traits
* `bcr-ebill-persistence` - persistence traits and SurrealDB implementation
* `bcr-ebill-transport` - network transport API traits and Nostr implementation
* `bcr-ebill-api` - API of the E-Bills project, contains most of the business logic
* `bcr-ebill-wasm` - Entrypoint for WASM version of the E-Bill API

### Entrypoint

There is a `WASM` entry point into the API. You can find the documentation to build and configure it [here](docs/index.md):

### Tests

You can run the existing tests using the following commands in the project root:

```bash
// without logs
cargo test

// with logs - (env_logger needs to be activated in the test to show logs)
RUST_LOG=info cargo test -- --nocapture
```

## Contribute

Check out the project [contributing guide](./CONTRIBUTING.md).
