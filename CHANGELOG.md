# 0.4.6

* Add basic logic for implementing (social) identity proofs
* Add persistence, basic service layer and WASM API for identity proofs

# 0.4.5

* Add handling for `RemoveSignatory` from company, which flags the company as not active
* Email Notifications
    * Add email notifications API
    * Add email notifications registration API
    * Add email notifications sending logic
* Fix issue where the notification sender defaulted to the personal identity instead of the signer identity
* Added `app_url` property to config - defaults to `https://bitcredit-dev.minibill.tech` (config break)
* Small fix to WASM build addressing the rustwasm organization archiving
* Added an API call `sync_bill_chain`, which re-synchronizes a bill via Nostr

# 0.4.4

* Add `num_confirmations_for_payment` config flag and a `payment_config` part of the api config, to configure the amount of confirmations needed until an on-chain payment is considered `paid`
* Rewrite payment logic to iterate transactions and calculate payment state based on the first transaction that covers the amount
    * We now are also able to differentiate between a payment not being sent, being in the mem pool, being paid and unconfirmed and paid and confirmed
    * Add payment state for sell, recourse and bill payments to DB (breaking DB change - reset IndexedDB)
    * Restructure `BillCurrentWaitingState` to remove duplication (breaking API change - check `index.d.ts`)
        * Add info for if a payment is in the mempool with it's transaction id, as well as how many confirmations it has, in the bill data (breaking DB change - reset IndexedDB)
* Removed the `gloo` dependency, since it's going to be archived
* Add chain propagation for company chains and identity chain
* Implement recovery for personal identity, company identities and bills

# 0.4.3

* Add endpoints to fetch files as base64 for identity, contacts, companies and bills
* Add option to remove files for identity, contacts and companies - if the file upload id in the payload is missing, it's ignored, if it's explicitly set to undefined, the file is removed
* Fix blank email validation for contacts and identities
* Add different file size limits for pictures (avatar/logo - 20k) and documents (invoices, registration, passport - 1mb) as well as an upper limit for bill files (100)
    * This limit is checked at creation/update time, not at the time of uploading a temporary file
* Add the address of the signer for the calls to `endorsements` and `past_endorsees`
* Add api call `active_notifications_for_node_ids` on `notification` API, which returns for a set of node ids, whether they have active notifications
    * If the set of node ids is empty, only the node ids that have active notifications are returned

# 0.4.2

* Add logic to get endorsees from plaintext chain
* Use new payload for requesting to mint (Breaking - has to be coordinated with Wildcat deployment of [this PR](https://github.com/BitcreditProtocol/Wildcat/pull/260))

# 0.4.1

* Add file and pub key to bill to share with external party and add accessors to extract data
* Upgrade wildcat and wallet-core dependencies

# 0.4.0

* Switch to new chain transport leveraging public Nostr threads
* Add `plaintext_hash` to Identity, Company and Bill Blocks, which is a hash over the plaintext data
    * (breaks all chains in the DB)
* Add functionality for sharing a bill with an external party, encrypted, hashed, and signed, with the plaintext block data
* Change visibility of `bill_service::error` and `bill_service::service` to private, moving the used types to `bill_service`
* Add cargo deny

# 0.3.17

* Changed minted proofs token format from cashu Token v3 to BitcrB (v4)
* Use NodeId, PublicKey, SecretKey and BillId types internally instead of strings (fully breaking)
    * This breaks all existing databases, since the node ids and bill ids now have the format `prefix|network|pubkey`- example: `bitcrt03f9f94d1fdc2090d46f3524807e3f58618c36988e69577d70d5d4d1e9e9645a4f`
    * The `prefix` is `bitcr`
    * The `network` character is as follows:
        * m => Mainnet
        * t => Testnet
        * T => Testnet4
        * r => Regtest
    * The `pubkey` is a stringified secp256k1 public key
    * Existing apps need to a.) delete their IndexedDB and b.) their localhost (because the mint ID might be in there)
* Removed `NodeId` trait and replaced it with a concrete method on the corresponding types (breaking API change)
* Rename `BillId` TS type to `BillIdResponse` (breaking TS type)

# 0.3.16

* Set the BTC network in the identity and check, if the persisted network is the same as the one configured in the application, failing if it doesn't.
* Nostr npub as primary key in Nostr contacts (breaking DB change)
* Add default mint to nostr contacts as default, so it doesn't have to be added to contacts anymore

# 0.3.15-hotfix1

* Fix Bill Caching issue between multiple identities

# 0.3.15

* Upload and download files to and from Nostr using Blossom
  * Add `nostr_hash` to `File` (breaking DB change)
* Fix MintRequestResponse return type
* Bill Caching for multiple identities (breaking DB change)

# 0.3.14

* Minting
  * Added notifications and offers
  * Added timestamps for status
  * Call mint endpoint for cancelling
  * Use mint nostr relays from network and fall back to identity ones
  * Add endpoints to accept, or reject an offer from a mint
  * Add logic to check keyset info, mint and create proofs
  * Add logic to recover proofs if something goes wrong
  * Add logic to check if proofs were spent

# 0.3.13

* Minting
  * Add default mint configuration options
    * `default_mint_url`
    * `default_mint_node_id`
  * Implement `request_to_mint`
  * Add minting status flag to bill
  * Add endpoint to fetch minting status for a bill
  * Add logic for checking mint request status on the mint
  * Add cronjob to check mint requests
  * Add endpoint to cancel mint requests
* Change bitcoin addresses and descriptor to p2wpkh
* Suppress logging from crates we don't control

# 0.3.12

* impl Default for BillParticipant and BillAnonParticipant
* Expose Receiver type for the PushApi trait
* Fix SurrealDB Memory leak for WASM

# 0.3.11

* Add LICENSE to crates
* Remove the `bcr-ebill-web` crate
* Use a list of Nostr relays everywhere, instead of a single one, including in the config
* Add Blank Endorse Bill data model implementation
  * Rename `IdentityPublicData` to `BillIdentParticipant`
    * same for `LightIdentityPublicData`
  * Introduce the concept of `BillParticipant`, with the variants `Ident` and `Anon`
    * `Anon` includes a `BillAnonParticipant`
    * `Ident` includes a `BillIdentParticipant`
  * Use `BillParticipant` in parts of the bill where a participant can be anonymous
* Add the possibility to add anonymous contacts
  * They only have Node Id, Name and E-Mail as fields
  * E-Mail is optional
  * This changes the data model for contacts, `email` and `postal_address` are now optional
    * Additional validation rules ensure the fields can only be set for non-anon contacts
  * Adds an endpoint `Api.contact().deanonymize()` to de-anonymize a contact by adding all necessary fields for a personal, or company contact
    * It takes the same payload as creating a contact and fails for non-anon contacts
* Add the possibility to add an anonymous identity
  * They only have Node Id, (nick)name and E-Mail as fields
  * E-Mail is optional
  * Adds an endpoint `Api.identity().deanonymize()` to de-anonymize an identity by adding all necessary fields for a personal identity
    * It takes the same payload as creating an identity and fails for a non-anon identity
  * Anon identity can't issue bills, or create a company
* Add the possibility to issue and endorse blank
  * New `Api.bill()` methods for blank endorsements
    * `issue_blank`
    * `offer_to_sell_blank`
    * `endorse_bill_blank`
    * `mint_bill_blank`
  * Can issue (non-self-drafted) blank bills (payee is anon)
  * Can endorse/mint/offer to sell to anon endorsee/mint/buyer
  * If caller of a bill action is anonymous in the bill, any action they take stay anonymous (e.g. endorse)
* Add endpoint to check payment for singular bill
  * `Api.bill().check_payment_for_bill(id)`
* Fix TS type for identity detail
* Return identity on `create` and `deanonymize` identity for consistency

# 0.3.10

* Change default testnet block explorer to `https://esplora.minibill.tech`
* Add LICENSE to npm package
* Reduce size of the WASM binary
* Fix a small issue, where bills were recalculated instead of taken from cache, once their payment/sell/recourse/accept requests expired
* Change behaviour of request to pay
  * it's now possible to req to pay before the maturity date
  * The actual payment expiry still only happens 2 workdays after the end of the maturity date,
    or end of the req to pay end of day if that was after the maturity date
  * the `request_to_pay_timed_out` flag is set after payment expired, not after the req to pay expired
  * The waiting state for payment is only active during the req to pay (while it's blocked)
    * Afterwards, the bill is not blocked anymore, can still be rejected to pay and paid
    * But recourse is only possible after the payment expired (after maturity date)
  * An expired req to pay, which expired before the maturity date does not show up in `past_payments`

# 0.3.9

* Add possibility to use a local regtest esplora setup for payment

# 0.3.8

* Add `esplora_base_url` as config parameter to be able to use a custom esplora based block explorer
* Add `node_ids` filter to `list` notifications endpoint
* Fixed an issue where events weren't propagated if no one was subscribed to the push notifications
* Run payment checks on startup

# 0.3.7

* Fix request recourse to accept validation - does not require a request to accept anymore

# 0.3.6

* Add validation for maturity date
* Add docs for testing
* Fix reject to accept not showing correctly without req to accept
* Add endpoint `clear_bill_cache` to clear the bill cache

# 0.3.5

* Properly propagate and log errors when getting a file (e.g. an avatar)
* Several fixes to recourse bill action validation
* Add in-depth tests for bill validation
* Fix not checking contact for company files

# 0.3.4

* Add in-depth tests for bill validation
* Add recourse reason to `Recourse` block data
  * (breaks existing persisted bills, if they had a recourse block)
* Added `has_requested_funds` flag to `BillStatusWeb`, indicating the caller has requested funds (req to pay, req to recourse, offer to sell) at some point
* Added `past_payments` endpoint to `Api.bill()`, which returns data about past payments and payment requests where the caller was the beneficiary

# 0.3.3

* Use Nip-04 as a default for Nostr communication
* Add incoming bill validation
* Add block data validation
* Add bill action validation for incoming blocks
* Add signer verification for incoming blocks
* Add recourse reason to `RequestRecourse` block data
  * (breaks existing persisted bills, if they had a request recourse block)
* Move bill validation logic to `bcr-ebill-core`

# 0.3.2

* Fixed `request_to_accept` calling the correct action
* Multi-identity Nostr consumer and currently-active-identity-sending
* Added more thorough logging, especially debug logging
* Expose Error types to TS
* Use string for `log_level` in config

# 0.3.1

* Persist active Identity to DB for WASM
* Change indexed-db name to "data"
* Use a different indexed-db collection for files, named "files"
* Create a new indexeddb database connection for each query to avoid transaction overlapping
* Removed timezone db api
* Persist base64 string instead of bytes for images, for more efficiency
* Added Retry-sending for Nostr block events
* Added block propagation via Nostr
* Added a caching layer for bills, heavily improving performance
* Added `error` logs for all errors returned from the API for the WASM version
* Added `log_level` to Config, which defaults to `info`
* Changed the API for uploading files to bill to use `file` instead of `files`.
So files can only be uploaded individually, but for `issue()`, `file_upload_ids`
can be passed - a list of file upload ids, to upload multiple files for one bill.
* Restructured `BitcreditBillWeb` to a more structured approach, separating `status`,
`data` and `participants` and adding the concept of `current_waiting_state`, to
have all data available, if the bill is in a waiting state.
  * Added the concept of `redeemed_funds_available` on `status`, to indicate if
    the caller has funds available (e.g. from a sale, or a paid bill)

# 0.3.0

* First version exposing a WASM API
