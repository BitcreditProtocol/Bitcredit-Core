# Usage:
# just pay <address> <amount>
# Example:
# just pay mtsCkPiHCE5gdvhV9aGD4AbpArMQADc3Ju 1.0

pay address amount:
    @echo "Loading wallet..."
    docker exec -it esplora-esplora-1 /srv/explorer/bitcoin/bin/bitcoin-cli -regtest -rpcwallet=default -rpccookiefile=/data/bitcoin/regtest/.cookie loadwallet default || true

    @echo "generate funds..."
    docker exec -it esplora-esplora-1 /srv/explorer/bitcoin/bin/bitcoin-cli -regtest -rpcwallet=default -rpccookiefile=/data/bitcoin/regtest/.cookie -generate 1 || true

    @echo "Sending {{amount}} BTC to {{address}}..."
    docker exec -it esplora-esplora-1 /srv/explorer/bitcoin/bin/bitcoin-cli -regtest -rpcwallet=default -rpccookiefile=/data/bitcoin/regtest/.cookie sendtoaddress {{address}} {{amount}}

    @echo "Mining block to {{address}}..."
    docker exec -it esplora-esplora-1 /srv/explorer/bitcoin/bin/bitcoin-cli -regtest -rpcwallet=default -rpccookiefile=/data/bitcoin/regtest/.cookie generatetoaddress 1 {{address}}

    @echo "Done."

check: wasm
  cargo fmt -- --check
  cargo check
  cargo test --all
  cargo clippy --all-targets --all-features -- -D warnings

wasm:
  wasm-pack build --dev --target web --out-name index ./crates/bcr-ebill-wasm
