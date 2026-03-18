# bdk-cli

You can use [bdk-cli](https://docs.rs/bdk-cli) for a local wallet to interact e.g. with testnet (sweep from a descriptor, or send transactions)

You can install it with `cargo install bdk-cli --features esplora`

Then, you can use the `justfile` in the project root to check balance, sync the wallet, or send transactions:

Example with descriptor `tr(cPHbchvqgi9ACegotAK34Hr17RokaeEqavMdsRw3XuWtghXBUYU2)#ujfsz6y4` - you can get this from E-Bill.

First, sync the wallet:

```bash
just sync "tr(cPHbchvqgi9ACegotAK34Hr17RokaeEqavMdsRw3XuWtghXBUYU2)#ujfsz6y4"
```

Then, check the balance:

```bash
just balance "tr(cPHbchvqgi9ACegotAK34Hr17RokaeEqavMdsRw3XuWtghXBUYU2)#ujfsz6y4"
```

Then, create a transaction, e.g. to `tb1qlzxh9zqzc0cfurkwjnua0ar0schh35f3836ngm` for `1000` sats

```bash
just create-tx "tr(cPHbchvqgi9ACegotAK34Hr17RokaeEqavMdsRw3XuWtghXBUYU2)#ujfsz6y4" "tb1qlzxh9zqzc0cfurkwjnua0ar0schh35f3836ngm" "1000"
```

You get back a psbt, copy it:

```json
{
  "psbt": "cHNidP8BAH0CAAAAAU+9ysDBsXEOTvLxf+iqIZ3oHi84nbGrAxqZODAJCfLgAAAAAAD9////AhEPAAAAAAAAIlEgKe6CL/nGFxAJO2lBNL6AfEH3xUZgWoLYLkpXmSllos/oAwAAAAAAABYAFPiNcogCw/CeDs6U+df0b4YveNExmotKAAABASuIEwAAAAAAACJRICnugi/5xhcQCTtpQTS+gHxB98VGYFqC2C5KV5kpZaLPIRabEPKjHZfz2Z/TMiYD0NKsGvKPtRwPQws5aKX1cwo3ywUAGl+PrgEXIJsQ8qMdl/PZn9MyJgPQ0qwa8o+1HA9DCzlopfVzCjfLAAEFIJsQ8qMdl/PZn9MyJgPQ0qwa8o+1HA9DCzlopfVzCjfLIQebEPKjHZfz2Z/TMiYD0NKsGvKPtRwPQws5aKX1cwo3ywUAGl+PrgAA"
}
```

Then, sign the transaction using the copied psbt:

```bash
just sign "tr(cPHbchvqgi9ACegotAK34Hr17RokaeEqavMdsRw3XuWtghXBUYU2)#ujfsz6y4" cHNidP8BAH0CAAAAAU+9ysDBsXEOTvLxf+iqIZ3oHi84nbGrAxqZODAJCfLgAAAAAAD9////AhEPAAAAAAAAIlEgKe6CL/nGFxAJO2lBNL6AfEH3xUZgWoLYLkpXmSllos/oAwAAAAAAABYAFPiNcogCw/CeDs6U+df0b4YveNExmotKAAABASuIEwAAAAAAACJRICnugi/5xhcQCTtpQTS+gHxB98VGYFqC2C5KV5kpZaLPIRabEPKjHZfz2Z/TMiYD0NKsGvKPtRwPQws5aKX1cwo3ywUAGl+PrgEXIJsQ8qMdl/PZn9MyJgPQ0qwa8o+1HA9DCzlopfVzCjfLAAEFIJsQ8qMdl/PZn9MyJgPQ0qwa8o+1HA9DCzlopfVzCjfLIQebEPKjHZfz2Z/TMiYD0NKsGvKPtRwPQws5aKX1cwo3ywUAGl+PrgAA
```

You get back a signed psbt, copy it:

```json
{
  "is_finalized": true,
  "psbt": "cHNidP8BAH0CAAAAAU+9ysDBsXEOTvLxf+iqIZ3oHi84nbGrAxqZODAJCfLgAAAAAAD9////AhEPAAAAAAAAIlEgKe6CL/nGFxAJO2lBNL6AfEH3xUZgWoLYLkpXmSllos/oAwAAAAAAABYAFPiNcogCw/CeDs6U+df0b4YveNExmotKAAABASuIEwAAAAAAACJRICnugi/5xhcQCTtpQTS+gHxB98VGYFqC2C5KV5kpZaLPAQhCAUD+SbgdjwDLdzv5rp6e9t8BvZfmbhl0n76CuzGSLQ+Z1SsO98ooFIXjJ70ddcT/gm7n9bM+o6AE71CSWHIQhk8TAAEFIJsQ8qMdl/PZn9MyJgPQ0qwa8o+1HA9DCzlopfVzCjfLAAA="
}
```

Finally, broadcast the transaction using the copied signed psbt

```bash
just broadcast "tr(cPHbchvqgi9ACegotAK34Hr17RokaeEqavMdsRw3XuWtghXBUYU2)#ujfsz6y4" cHNidP8BAH0CAAAAAU+9ysDBsXEOTvLxf+iqIZ3oHi84nbGrAxqZODAJCfLgAAAAAAD9////AhEPAAAAAAAAIlEgKe6CL/nGFxAJO2lBNL6AfEH3xUZgWoLYLkpXmSllos/oAwAAAAAAABYAFPiNcogCw/CeDs6U+df0b4YveNExmotKAAABASuIEwAAAAAAACJRICnugi/5xhcQCTtpQTS+gHxB98VGYFqC2C5KV5kpZaLPAQhCAUD+SbgdjwDLdzv5rp6e9t8BvZfmbhl0n76CuzGSLQ+Z1SsO98ooFIXjJ70ddcT/gm7n9bM+o6AE71CSWHIQhk8TAAEFIJsQ8qMdl/PZn9MyJgPQ0qwa8o+1HA9DCzlopfVzCjfLAAA=
```

You get back a transaction id, which you can check on esplora:

```json
{
  "txid": "fa45e99db4d139383a0d11687ae11c16e9b56633875b6f5d1f12dc80158d45d3"
}
```

Esplora Link: [https://esplora.minibill.tech/testnet/tx/fa45e99db4d139383a0d11687ae11c16e9b56633875b6f5d1f12dc80158d45d3](https://esplora.minibill.tech/testnet/tx/fa45e99db4d139383a0d11687ae11c16e9b56633875b6f5d1f12dc80158d45d3)
