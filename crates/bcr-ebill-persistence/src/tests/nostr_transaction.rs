use crate::{
    NostrChainEventStoreApi,
    traits::{nostr::NostrChainEvent, transaction::TransactionManagerApi},
};
use bcr_ebill_core::protocol::{Sha256Hash, Timestamp, blockchain::BlockchainType};
use nostr::event::FinalizeEvent;

fn make_chain_event(
    chain_id: &str,
    chain_type: BlockchainType,
    block_height: usize,
    marker: &str,
) -> NostrChainEvent {
    let payload = nostr::event::EventBuilder::new(nostr::event::Kind::TextNote, marker)
        .finalize(&nostr::key::Keys::generate())
        .expect("could not create test nostr event");
    NostrChainEvent {
        event_id: payload.id.to_string(),
        root_id: payload.id.to_string(),
        reply_id: None,
        author: payload.pubkey.to_string(),
        chain_id: chain_id.to_owned(),
        chain_type,
        block_height,
        block_hash: Sha256Hash::new(marker),
        received: Timestamp::new(1_700_000_000).unwrap(),
        time: Timestamp::new(1_700_000_000).unwrap(),
        payload,
    }
}

pub async fn test_nostr_transaction_commit<M, S>(manager: &M, store: &S)
where
    M: TransactionManagerApi + ?Sized,
    S: NostrChainEventStoreApi + ?Sized,
{
    let chain_id = "nostr-transaction-commit";
    let old_bill_event = make_chain_event(chain_id, BlockchainType::Bill, 1, "old-bill-event");
    let company_event = make_chain_event(chain_id, BlockchainType::Company, 1, "company-event");
    store
        .add_chain_event(old_bill_event.clone())
        .await
        .expect("could not seed old bill event");
    store
        .add_chain_event(company_event.clone())
        .await
        .expect("could not seed company event");
    let replacement_bill_event =
        make_chain_event(chain_id, BlockchainType::Bill, 2, "replacement-bill-event");
    let mut tx = manager.begin().await.expect("could not begin transaction");
    tx.remove_chain_events(chain_id, BlockchainType::Bill)
        .await
        .expect("could not remove bill chain events");
    tx.add_chain_event(&replacement_bill_event)
        .await
        .expect("could not add replacement bill event");
    tx.commit().await.expect("could not commit transaction");
    let bill_events = store
        .find_chain_events(chain_id, BlockchainType::Bill)
        .await
        .expect("could not read bill events");
    assert_eq!(bill_events.len(), 1);
    assert_eq!(bill_events[0].event_id, replacement_bill_event.event_id);
    assert_eq!(bill_events[0].block_hash, replacement_bill_event.block_hash);
    assert_eq!(bill_events[0].block_height, 2);
    assert!(
        store
            .by_event_id(&old_bill_event.event_id)
            .await
            .expect("could not query old bill event")
            .is_none()
    );
    let company_events = store
        .find_chain_events(chain_id, BlockchainType::Company)
        .await
        .expect("could not read company events");
    assert_eq!(company_events.len(), 1);
    assert_eq!(company_events[0].event_id, company_event.event_id);
}

pub async fn test_nostr_transaction_rollback<M, S>(manager: &M, store: &S)
where
    M: TransactionManagerApi + ?Sized,
    S: NostrChainEventStoreApi + ?Sized,
{
    let chain_id = "nostr-transaction-rollback";
    let old_bill_event = make_chain_event(chain_id, BlockchainType::Bill, 1, "old-bill-event");
    let company_event = make_chain_event(chain_id, BlockchainType::Company, 1, "company-event");
    store
        .add_chain_event(old_bill_event.clone())
        .await
        .expect("could not seed old bill event");
    store
        .add_chain_event(company_event.clone())
        .await
        .expect("could not seed company event");
    let replacement_bill_event =
        make_chain_event(chain_id, BlockchainType::Bill, 2, "replacement-bill-event");
    let mut tx = manager.begin().await.expect("could not begin transaction");
    tx.remove_chain_events(chain_id, BlockchainType::Bill)
        .await
        .expect("could not remove bill chain events");
    tx.add_chain_event(&replacement_bill_event)
        .await
        .expect("could not add replacement bill event");
    drop(tx);
    let bill_events = store
        .find_chain_events(chain_id, BlockchainType::Bill)
        .await
        .expect("could not read bill events");
    assert_eq!(bill_events.len(), 1);
    assert_eq!(bill_events[0].event_id, old_bill_event.event_id);
    assert_eq!(bill_events[0].block_hash, old_bill_event.block_hash);
    assert_eq!(bill_events[0].block_height, 1);
    assert!(
        store
            .by_event_id(&replacement_bill_event.event_id)
            .await
            .expect("could not query replacement bill event")
            .is_none()
    );
    let company_events = store
        .find_chain_events(chain_id, BlockchainType::Company)
        .await
        .expect("could not read company events");
    assert_eq!(company_events.len(), 1);
    assert_eq!(company_events[0].event_id, company_event.event_id);
}
