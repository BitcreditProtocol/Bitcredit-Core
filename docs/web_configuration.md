# Web Configuration

The application can be configured using command-line parameters, or environment variables

The following options are available:

* `HTTP_PORT` / `--http-port` - the HTTP address (default: 8000)
* `HTTP_ADDRESS` / `--http-address` - the HTTP address (default: 127.0.0.1)
* `DATA_DIR` - the data directory root (default: ".")
* `SURREAL_DB_CONNECTION` - the surreal DB connection (default: "ws://localhost:8800") - set to `rocksdb://data/surreal` for embedded mode
* `BITCOIN_NETWORK` - bitcoin network to use (default: testnet), possible values: `mainnet`, `regtest`, `testnet4` and `testnet`
* `RUST_LOG` - the log level, e.g.: info, trace, debug, error (default: error)
* `NOSTR_RELAY` - nostr relay endpoint (default: ws://localhost:8080)
* `MINT_URL` - cashu mint endpoint (default: https://moksha.minibill.tech)
* `JOB_RUNNER_INITIAL_DELAY_SECONDS` - initial delay until cron jobs run (default: 1)
* `JOB_RUNNER_CHECK_INTERVAL_SECONDS` - interval in which cron jobs run (default: 600)
* `FRONTEND_URL_PATH` - default path to serve the frontend from (default: /)
* `FRONTEND_SERVE_FOLDER` - folder where the static frontend is served from (default: ./frontend)
* `LAUNCH_FRONTEND_AT_STARTUP` - open the frontend in a browser on startup (default: false)
* `ESPLORA_BASE_URL` - The base url of the esplora URL for payment checks (default: https://esplora.minibill.tech)

## Example

```bash
RUST_LOG=info cargo run -- --http-port 8001

RUST_LOG=info HTTP_PORT=8001 cargo run
```

