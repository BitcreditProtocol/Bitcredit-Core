# Esplora

To check the bitcoin blockchain, we use the [Esplora](https://github.com/Blockstream/esplora) API.

You can either use a publicly running service such as [Blockstream](https://blockstream.info/testnet/), or run a local regtest-based
Esplora instance using Docker.

## Configuration

The `esplora_base_urls` config option accepts either:
- An array of URLs (recommended): First URL is primary, subsequent URLs are fallbacks on 5xx server errors
- A single URL string (legacy, for backward compatibility)

### Regtest Example

For local regtest, set the config to use `regtest` as a bitcoin network:

```javascript
  let config = {
    log_level: "debug",
    bitcoin_network: "regtest",
    esplora_base_urls: ["http://localhost:8094"],
    nostr_relays: ["wss://bcr-relay-dev.minibill.tech"],
    job_runner_initial_delay_seconds: 1,
    job_runner_check_interval_seconds: 600,
  };
```

### Production Example with Fallback

For production with fallback to Blockstream's public API:

```javascript
  let config = {
    bitcoin_network: "testnet",
    esplora_base_urls: [
      "https://esplora.minibill.tech",
      "https://blockstream.info"
    ],
    // ... other options
  };
```

## Running Local Esplora

In the repository root, navigate to `./esplora` and run:

```bash
docker-compose up
```

This runs a regtest based Esplora instance, which you can interact with like this:

```bash
# load default wallet
docker exec -it esplora-esplora-1 /srv/explorer/bitcoin/bin/bitcoin-cli -regtest -rpcwallet=default -rpccookiefile=/data/bitcoin/regtest/.cookie loadwallet default

# generate blocks
docker exec -it esplora-esplora-1 /srv/explorer/bitcoin/bin/bitcoin-cli -regtest -rpcwallet=default -rpccookiefile=/data/bitcoin/regtest/.cookie -generate 10
```

You can also use the `justfile` to send a payment to a given address like this:

```bash
just pay mtsCkPiHCE5gdvhV9aGD4AbpArMQADc3Ju 1.0
```

This will send the payment and mine a block and then you can check it here: [http://localhost:8094/regtest/address/mtsCkPiHCE5gdvhV9aGD4AbpArMQADc3Ju](http://localhost:8094/regtest/address/mtsCkPiHCE5gdvhV9aGD4AbpArMQADc3Ju)

