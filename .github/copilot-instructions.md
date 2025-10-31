# Copilot Instructions for E-Bills Project

## Project Overview

**E-Bills** is a Rust-based project for the Bitcredit E-Bills system, primarily targeting **WebAssembly (WASM)** as the main execution environment. The project provides a core API for managing electronic bills with Bitcoin integration, Nostr-based transport, and SurrealDB persistence.

## Project Structure

This is a Rust workspace with the following crates:

- **`bcr-ebill-core`** - Core data models, validation logic, and traits for bills, contacts, companies, and blockchain operations
- **`bcr-ebill-persistence`** - Persistence traits and SurrealDB implementation (uses IndexedDB in WASM)
- **`bcr-ebill-transport`** - Network transport API traits with Nostr protocol implementation
- **`bcr-ebill-api`** - Main business logic and service layer integrating all components
- **`bcr-ebill-wasm`** - **Primary entrypoint** - WASM bindings and JavaScript/TypeScript API surface

### Key Dependencies

- Bitcoin operations: `bitcoin`, `bip39`, `miniscript`, `secp256k1`
- WASM integration: `wasm-bindgen`, `tsify`, `serde-wasm-bindgen`
- Transport: `nostr`, `nostr-sdk` (for decentralized communication)
- Database: `surrealdb` (IndexedDB for WASM, other backends for native)
- Async runtime: `tokio` and `tokio_with_wasm` for cross-platform async support
- Internal dependencies: `bcr-common`, `bcr-wallet-lib` (from BitcreditProtocol organization)

## Architecture Principles

### WASM-First Design

1. **Target Environment**: The primary execution environment is WebAssembly running in browsers
2. **Database**: Uses IndexedDB via SurrealDB in WASM builds (`indxdb://default` connection string)
3. **Platform Abstraction**: Code must work in both single-threaded (WASM) and multi-threaded environments
   - Use `ServiceTraitBounds` trait for platform-specific trait bounds
   - `Send + Sync` on native, no bounds on `wasm32`
4. **Async Runtime**: Use `tokio_with_wasm` for WASM compatibility, `tokio` for native

### Core Architecture Layers

```
┌─────────────────────────────────────┐
│   bcr-ebill-wasm (WASM API)        │  ← TypeScript bindings, JS interface
├─────────────────────────────────────┤
│   bcr-ebill-api (Business Logic)   │  ← Services, orchestration
├─────────────────────────────────────┤
│   bcr-ebill-transport (Nostr)      │  ← Network communication
│   bcr-ebill-persistence (DB)       │  ← Data storage
├─────────────────────────────────────┤
│   bcr-ebill-core (Domain Models)   │  ← Core types, validation
└─────────────────────────────────────┘
```

## Key Concepts

### Bill Lifecycle

E-Bills follow a complex state machine with multiple roles:
- **Drawer**: Bill issuer
- **Payer**: Bill drawee (who pays)
- **Holder**: Current bill holder (payee or endorsee)
- **Contingent**: Guarantee chain participant
- **Recoursee**: Participant being recoursed against
- **Buyer**: User to sell bill to

### Bill States

Bills have multi-dimensional states:
1. **Acceptance State**: requested → accepted/rejected/expired
2. **Payment State**: requested → paid/rejected/expired
3. **Recourse States**: List of recourse transactions (latest first)
4. **Sell States**: List of sale transactions (latest first)
5. **Mint State**: Whether bill was minted

See `docs/concepts.md` for detailed state machine documentation.

### Blockchain Structure

Bills use a blockchain-like structure with blocks representing actions. Each action creates a new block in the bill's chain.

## Development Guidelines

### Code Style

1. **Formatting**: Use `cargo fmt` (configuration in `rustfmt.toml`)
2. **Linting**: Use `cargo clippy` (configuration in `clippy.toml`)
   - `too-many-arguments-threshold=200` is configured
3. **Validation**: Implement `Validate` trait for all domain types
4. **Error Handling**: Use `thiserror` for error types, `anyhow` for contexts

### Testing Strategy

- **Core**: Thorough unit tests for validation and blockchain logic
- **Persistence**: Unit tests for database operations
- **Transport**: Unit tests for Nostr communication
- **API**: Integration tests combining components
- **WASM**: Basic wiring tests

Run tests with:
```bash
cargo test                        # Without logs
RUST_LOG=info cargo test -- --nocapture  # With logs
```

### WASM Development

#### Building WASM

```bash
# Development build
wasm-pack build --dev --target web --out-name index ./crates/bcr-ebill-wasm

# Release build (optimized)
wasm-pack build --target web ./crates/bcr-ebill-wasm
```

Or use the justfile:
```bash
just wasm  # Development build
```

#### TypeScript Bindings

Use `tsify` for automatic TypeScript generation from Rust types:

**For structs/types:**
```rust
use tsify::Tsify;

#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct MyType {
    field: String,
}
```

**For API functions:**
```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
impl MyApi {
    #[wasm_bindgen(unchecked_return_type = "MyReturnType")]
    pub async fn my_function(
        &self,
        #[wasm_bindgen(unchecked_param_type = "MyParamType")] payload: JsValue,
    ) -> Result<JsValue> {
        let param: MyParamType = serde_wasm_bindgen::from_value(payload)?;
        // ... logic
        let result = serde_wasm_bindgen::to_value(&response)?;
        Ok(result)
    }
}
```

**For numeric enums:**
```rust
#[wasm_bindgen]
#[repr(u8)]
#[derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
pub enum MyEnum {
    Variant1 = 0,
    Variant2 = 1,
}
```

**For string-based enums:**
```rust
#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum MyEnum {
    Variant1,
    Variant2,
}
```

#### Testing WASM Locally

```bash
# Build and serve
just wasm
just serve

# Or manually
wasm-pack build --dev --target web ./crates/bcr-ebill-wasm
http-server -g -c-1 -p 8081 ./crates/bcr-ebill-wasm/
```

Access at http://localhost:8081/ and use browser DevTools (Storage tab) to inspect IndexedDB.

### Configuration

WASM apps require initialization with config:

```javascript
let config = {
    bitcoin_network: "testnet",           // mainnet, testnet, testnet4, regtest
    esplora_base_url: "https://esplora.minibill.tech",
    nostr_relays: ["wss://bcr-relay-dev.minibill.tech"],
    surreal_db_connection: "indxdb://default",  // IndexedDB for WASM
    data_dir: ".",
    job_runner_initial_delay_seconds: 1,
    job_runner_check_interval_seconds: 600,
};

await wasm.default();
await wasm.initialize_api(config);
```

## Common Tasks

### Adding a New Feature

1. **Domain Model** (`bcr-ebill-core`): Add types with `Validate` trait
2. **Persistence** (`bcr-ebill-persistence`): Add repository traits and implementations
3. **Transport** (`bcr-ebill-transport`): Add network operations if needed
4. **Business Logic** (`bcr-ebill-api`): Add service methods
5. **WASM API** (`bcr-ebill-wasm`): Expose via WASM bindings with TypeScript types
6. **Tests**: Add unit tests at each layer, integration tests in API
7. **Documentation**: Update relevant docs in `docs/`

### Working with Bills

Bills are central to this system. Key files:
- `crates/bcr-ebill-core/src/bill/` - Bill types and validation
- `crates/bcr-ebill-core/src/blockchain/bill/` - Bill blockchain structure
- `crates/bcr-ebill-api/src/service/` - Bill business logic

### Bitcoin Integration

The project uses Bitcoin for payments. Key considerations:
- Support for multiple networks (mainnet, testnet, testnet4, regtest)
- Esplora integration for blockchain queries
- Miniscript for complex spending conditions
- Payment tracking via mempool and confirmations

### Nostr Transport

Communication uses the Nostr protocol:
- Decentralized relay-based messaging
- NIP-04 and NIP-59 support
- Configured via relay URLs in config

## Build and CI

### Quality Checks

Use the `check` recipe in justfile:
```bash
just check
```

This runs:
1. WASM build
2. Format check (`cargo fmt -- --check`)
3. Compilation check (`cargo check`)
4. All tests (`cargo test --all`)
5. Clippy lints (`cargo clippy --all-targets --all-features -- -D warnings`)
6. Dependency audit (`cargo deny check`)

### CI Pipeline

GitHub Actions workflow (`.github/workflows/`) runs on all branches:
- Format, build, test, lint checks
- Uses GitHub App token for private repo access (bcr-common, bcr-wallet-lib)
- Disk space optimization for limited runners

## Important Patterns

### Platform-Specific Code

```rust
#[cfg(not(target_arch = "wasm32"))]
pub trait ServiceTraitBounds: Send + Sync {}

#[cfg(target_arch = "wasm32")]
pub trait ServiceTraitBounds {}
```

### Validation Pattern

```rust
impl Validate for MyType {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validation logic
        Ok(())
    }
}
```

### Error Handling in WASM

```rust
#[derive(Tsify, Serialize)]
#[tsify(into_wasm_abi)]
struct JsErrorData {
    error: &'static str,
    message: String,
    code: u16,
}
```

JavaScript side uses try/catch:
```javascript
try {
    let result = await api.someMethod(params);
} catch (error) {
    // error has: { error, message, code }
}
```

## Documentation

- `README.md` - Project overview
- `CONTRIBUTING.md` - Links to contribution guidelines
- `docs/index.md` - Documentation index
- `docs/wasm.md` - WASM build and usage guide
- `docs/wasm_configuration.md` - Configuration reference
- `docs/concepts.md` - Bill lifecycle and state machine
- `docs/testing.md` - Testing strategy
- `docs/versioning.md` - Versioning guide
- `docs/wasm_releasing.md` - Release process

## External Resources

- NPM Package: `@bitcredit/bcr-ebill-wasm`
- GitHub Organization: BitcreditProtocol
- Contributing Guidelines: [Google Doc](https://docs.google.com/document/d/18468Jb_PT4Sn1YoiwsEIZmWXUb2opxEQzFyGGnwH5VQ)

## Notes for AI Assistants

1. **WASM is Primary**: Always consider WASM compatibility. Check for `wasm32` target when suggesting async or platform-specific code
2. **Type Safety**: Leverage Rust's type system and `Validate` trait for correctness
3. **TypeScript Bindings**: When modifying WASM API, ensure proper TypeScript type generation using `tsify` or `wasm_bindgen` annotations
4. **Testing**: Add tests at the appropriate layer (unit tests in core/persistence/transport, integration in API)
5. **Documentation**: Bill lifecycle is complex - refer to `docs/concepts.md` for state machine details
6. **Dependencies**: Some deps are from BitcreditProtocol private repos requiring GitHub App authentication
7. **Serialization**: Use `borsh` for internal serialization, `serde_json` for WASM boundaries
8. **Edition**: Project uses Rust 2024 edition
