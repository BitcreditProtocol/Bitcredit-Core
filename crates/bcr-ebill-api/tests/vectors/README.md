# Public signing vectors, v1

`cross-mint-and-directory-v1.json` is an exact copy of
`projects/Bitcredit-Core/crates/bcr-ebill-api/tests/vectors/cross-mint-and-directory-v1.json`.
It contains public, synthetic fixtures, never runtime credentials. Core generates them through
its internal unit-test path with the established public test identity (scalar 3), fixed timestamps,
fixed nonces and zero BIP340 auxiliary randomness. Production uses Core's clock, cryptographic
random nonces and randomized Schnorr signing. No deterministic signer is exported to JavaScript.

## Canonical bytes

All text is UTF-8. Grant and revoke fields are serialized as the following lines, in order,
with a single LF (`\n`) after **every** line, including the last. Seconds are unsigned decimal
integers. `network` is the Bitcoin Network display string (`regtest`, `testnet`, `testnet4`,
`signet`); mainnet (`bitcoin`) is refused. Node IDs retain their network prefix and compressed
public key; Mint keys and nonces are lowercase 64-character hex. UUIDs are canonical hyphenated
RFC4122 UUIDs. The only operation is `bill_status`.

Grant:

```text
cross-mint-grant-v1
grantId
network
subjectNodeId
requestingMintPubkey
answeringMintPubkey
bill_status
billId
caseBinding
issuedAt
expiresAt
nonce
```

Revoke:

```text
cross-mint-revoke-v1
grantId
network
subjectNodeId
requestingMintPubkey
answeringMintPubkey
nonce
issuedAt
```

Verify BIP340 Schnorr against `sha256(canonicalText)` and the subject NodeId's x-only key.
The grant's `expiresAt` is exclusive: reject at `now >= expiresAt`, even with a valid signature.
Core sets `issuedAt`, a default lifetime of 300 seconds (permitted range 1–300), and a fresh
32-byte nonce. Revoke uses a separate schema and fresh nonce. Verification must also enforce
expected network, subject, both named Mints, bill, case binding, single use and revocation;
a valid signature alone does not establish permission to disclose.

The listing uses NIP-01 instead: compact JSON array
`[0,pubkey,created_at,kind,tags,content]`, **without** a terminal newline. Its SHA256 is both
`messageSha256` and `event.id`; verify `event.sig` against that digest and `event.pubkey`.
Preserve the exact `content` string: parsing and reserializing it can change the signed bytes.
Listings have kind 38900, `d=yellow-book:v1:<network>` and `t=bitcredit-yellow-book-v1`.
Content binds schema/network/subject/status to the key and includes only reviewed public fields.
Withdrawal content is exactly `{schema,network,subjectNodeId,status:"withdrawn"}`. Its separate
kind-5 event targets IDs derived from verified prior signed listings through `e` tags, with
`k=38900` and `a=38900:<author>:yellow-book:v1:<network>`, never the withdrawal.
`withdrawal` contains the signed replacement and deletion pair. Inputs use
`{priorEvents: SignedDirectoryEvent[]}` (1–31 events); kind, author, network d-tag,
event ID and signature are verified before Core signs any deletion.
The listing expiry is exclusive and at most 30 days after creation. Text bounds count UTF-16
code units to match the TypeScript verifier; the complete signed event is bounded by UTF-8 bytes.

## Consuming the file in TypeScript

- `grant.signed` is `{grant,signature}`; `revoke.signed` is `{revoke,signature}`.
- Both entries include `canonicalText` and `messageSha256`. Compare the verifier's canonical
  bytes/hash before checking the signature using the top-level `publicKey`.
- `listing.event` is the complete Nostr event. `listing.canonicalText` is its NIP-01 array;
  `listing.messageSha256` is the expected event ID.
- Each `negative` entry names its target and expected rejection. The wrong-key case overrides
  only the verification public key. The mainnet case supplies a separately valid signature and
  canonical text: reject its network even though its signature verifies. Expired cases keep the
  original signed bytes and set `verifyAt`; reject at the exact expiry second.

Regenerate from the Core root (with its dependencies available):

```sh
BITCREDIT_REGENERATE_PUBLIC_VECTORS=1 cargo test -p bcr-ebill-api --features sqlite network_consent::tests::deterministic_cross_language_vectors_match
```

Copy the generated JSON here unchanged, then run the test again without the regeneration variable.
The regular test compares the whole fixture with independently reconstructed canonical data and
checks BIP340 and NIP-01 verification. The exported WASM methods are on `Api.identity()` and use
the existing `TSResult<T>` envelope. Input payloads reject unknown fields, including clocks,
nonces, private keys, subject IDs and schema overrides. Company listing requires the selected
company's key and a current authorized personal signatory; unsupported authority has no fallback
signature. The APIs sign and return public data; the host owns explicit consent review and delivery.


## Service voice admission

`service-voice-admission-v1.json` is copied unchanged from Core's vector directory.
`positive.signed` is `{admission,signature}`, with `canonicalText` and `messageSha256`.
The public test signer is the same scalar 3. Each UTF-8 field has a terminal LF:

```text
service-voice-admission-v1
network
subjectNodeId
serviceMintNodeId
issuedAt
expiresAt
nonce
```

Verify BIP340 over SHA256(text) using the subject NodeId's x-only key. The subject is
always the device operator's personal identity, including in a company-selected context.
The service Mint must equal the configured default Mint; application ownership at that
Mint is not a prerequisite. Core supplies the clock, a fresh 64-character lowercase-hex
nonce, and a 1–300 second lifetime (default 300). Reject mainnet, mismatched network or
service Mint, caller-injected fields, expiry at `now >= expiresAt`, and replay according
to the service Mint's policy. No key, bearer proof or financial authorization is returned.
The negative vectors include wrong service Mint and mainnet with otherwise valid
signatures, exact-boundary expiry, and verification under the wrong key.

Regenerate both files with
`BITCREDIT_REGENERATE_PUBLIC_VECTORS=1 cargo test -p bcr-ebill-api --features sqlite deterministic_`,
then copy both JSON files here and rerun without the regeneration variable.
