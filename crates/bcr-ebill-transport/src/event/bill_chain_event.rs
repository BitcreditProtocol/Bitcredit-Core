// TODO:
// - On issue bill publish a kind 1 event with the genesis block (plus potential metadata) and notifiy other participants
// about th bill Nostr event id and keys.
// - On add block publish a kind 1 reply message to either the genesis block or the latest block we
// find on Nostr for the bill. (needs fetching latest before adding block)

use bcr_ebill_core::{bill::BillKeys, blockchain::bill::BillBlock};
use serde::{Deserialize, Serialize};

/// A chain invite sent to new chain participants via private Nostr DM.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainInvite {
    pub bill_id: String,
    pub keys: BillKeys,
}

/// The encrypted BCR payload contained in a public block Nostr event.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainEvent {
    pub bill_id: String,
    pub block: BillBlock,
}
