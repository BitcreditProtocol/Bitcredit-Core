# WASM Configuration

The application can be configured using the `Config` struct.

```rust
pub struct Config {
    pub bitcoin_network: String,
    pub nostr_relay: String,
    pub esplora_base_url: String,
    pub surreal_db_connection: String,
    pub data_dir: String,
    pub job_runner_initial_delay_seconds: u32,
    pub job_runner_check_interval_seconds: u32,
}
```

It contains the following options:

* `bitcoin_network` - bitcoin network to use, possible values: `mainnet`, `regtest` and `testnet`
* `esplora_base_url` - bitcoin explorer base url for payment checks
* `nostr_relay` - nostr relay endpoint
* `surreal_db_connection` - the surreal DB connection
* `data_dir` - the data directory root - not used on the Web
* `job_runner_initial_delay_seconds` - initial delay until cron jobs run
* `job_runner_check_interval_seconds` - interval in which cron jobs run

## Example

```javascript
    let config = {
        bitcoin_network: "testnet",
        esplora_base_url: "https://blockstream.info",
        nostr_relay: "wss://bitcr-cloud-run-05-550030097098.europe-west1.run.app",
        surreal_db_connection: "indxdb://default",
        data_dir: ".",
        job_runner_initial_delay_seconds: 1,
        job_runner_check_interval_seconds: 600,
    };
```

