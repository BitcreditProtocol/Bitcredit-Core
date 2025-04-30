# Esplora

To check the bitcoin blockchain, we use the [Esplora](https://github.com/Blockstream/esplora) API.

You can either use a publicly running service such as [Blockstream](https://blockstream.info/testnet/), or run a local regtest-based
Esplora instance using Docker.

For this, you also have to set the config to use `regtest` as a bitcoin network and `http://localhost:8094` for the explorer:

```javascript
  let config = {
    log_level: "debug",
    bitcoin_network: "regtest",
    esplora_base_url: "http://localhost:8094",
    nostr_relay: "wss://bitcr-cloud-run-05-550030097098.europe-west1.run.app",
    job_runner_initial_delay_seconds: 1,
    job_runner_check_interval_seconds: 600,
  };
```

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

