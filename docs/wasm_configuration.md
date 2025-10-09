# WASM Configuration

The application can be configured using the `Config` struct.

```rust
pub struct Config {
    pub bitcoin_network: String,
    pub nostr_relays: Vec<url::url>,
    pub esplora_base_url: url::url,
    pub surreal_db_connection: String,
    pub data_dir: String,
    pub job_runner_initial_delay_seconds: u32,
    pub job_runner_check_interval_seconds: u32,
}
```

It contains the following options:

* `bitcoin_network` - bitcoin network to use, possible values: `mainnet`, `regtest`, `testnet4` and `testnet`
* `esplora_base_url` - bitcoin explorer base url for payment checks
* `nostr_relays` - the nostr relay endpoints
* `surreal_db_connection` - the surreal DB connection
* `data_dir` - the data directory root - not used on the Web
* `job_runner_initial_delay_seconds` - initial delay until cron jobs run
* `job_runner_check_interval_seconds` - interval in which cron jobs run

## Example

```javascript
    let config = {
        bitcoin_network: "testnet",
        esplora_base_url: "https://esplora.minibill.tech",
        nostr_relays: ["wss://bcr-relay-dev.minibill.tech"],
        surreal_db_connection: "indxdb://default",
        data_dir: ".",
        job_runner_initial_delay_seconds: 1,
        job_runner_check_interval_seconds: 600,
    };
```

