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
  cargo deny check

wasm:
  wasm-pack build --dev --target web --out-name index ./crates/bcr-ebill-wasm

serve:
  http-server -g -c-1 -p 8081 ./crates/bcr-ebill-wasm/

# bdk-cli
# to install:
# cargo install bdk-cli --features esplora
network := "testnet"
db_type := "sqlite"
client := "esplora"
url := "https://esplora.minibill.tech/testnet/api"

# Get Balance
# just balance <descriptor>
# Example:
# just balance "tr(cPHbchvqgi9ACegotAK34Hr17RokaeEqavMdsRw3XuWtghXBUYU2)#ujfsz6y4"
balance descriptor:
    bdk-cli \
        --network {{network}} \
        wallet \
        --database-type {{db_type}} \
        --client-type {{client}} \
        --url "{{url}}" \
        --ext-descriptor "{{descriptor}}" balance

# Sync
# You might have to call sync before sending a transaction to sync with the network, so your local wallet knows you have funds
# just sync <descriptor>
# Example:
# just sync "tr(cPHbchvqgi9ACegotAK34Hr17RokaeEqavMdsRw3XuWtghXBUYU2)#ujfsz6y4"
sync descriptor:
    bdk-cli \
        --network {{network}} \
        wallet \
        --database-type {{db_type}} \
        --client-type {{client}} \
        --url "{{url}}" \
        --ext-descriptor "{{descriptor}}" sync

# Send transaction - Usage:
# just create-tx <descriptor> <address> <amount>
# You will get back a psbt, then:
# just sign <descriptor> <psbt>
# You will get back a signed psbt, then
# just broadcast <descriptor> <psbt>
# Example:
# just create-tx "tr(cPHbchvqgi9ACegotAK34Hr17RokaeEqavMdsRw3XuWtghXBUYU2)#ujfsz6y4" "tb1qlzxh9zqzc0cfurkwjnua0ar0schh35f3836ngm" "1000"
create-tx descriptor address amount:
    bdk-cli \
        --network {{network}} \
        wallet \
        --database-type {{db_type}} \
        --client-type {{client}} \
        --url "{{url}}" \
        --ext-descriptor "{{descriptor}}" create_tx --to {{address}}:{{amount}}

# Sign PSBT
sign descriptor psbt:
    bdk-cli \
        --network {{network}} \
        wallet \
        --database-type {{db_type}} \
        --client-type {{client}} \
        --url "{{url}}" \
        --ext-descriptor "{{descriptor}}" sign {{psbt}}

# Broadcast PSBT
broadcast descriptor psbt:
    bdk-cli \
        --network {{network}} \
        wallet \
        --database-type {{db_type}} \
        --client-type {{client}} \
        --url "{{url}}" \
        --ext-descriptor "{{descriptor}}" broadcast --psbt {{psbt}}
