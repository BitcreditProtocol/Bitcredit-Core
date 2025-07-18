use std::{cmp::Reverse, collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bcr_ebill_core::{NodeId, ServiceTraitBounds, blockchain::BlockchainType, util::BcrKeys};
use bcr_ebill_persistence::{NostrChainEventStoreApi, nostr::NostrChainEvent};
use log::{debug, error, warn};

use crate::{
    Event, EventEnvelope, EventType, NotificationJsonTransportApi, Result,
    event::blockchain_event::{ChainInvite, ChainKeys},
    handler::public_chain_helpers::EventContainer,
};

use super::{NotificationHandlerApi, public_chain_helpers::collect_event_chains};

pub struct CompanyInviteEventHandler {
    transport: Arc<dyn NotificationJsonTransportApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationHandlerApi for CompanyInviteEventHandler {
    fn handles_event(&self, event_type: &EventType) -> bool {
        event_type == &EventType::CompanyChainInvite
    }

    async fn handle_event(
        &self,
        event: EventEnvelope,
        node_id: &NodeId,
        _: Box<nostr::Event>,
    ) -> Result<()> {
        debug!("incoming company chain invite for {node_id}");
        if let Ok(decoded) = Event::<ChainInvite>::try_from(event.clone()) {
            let events = self
                .transport
                .resolve_public_chain(&decoded.data.chain_id, decoded.data.chain_type)
                .await?;

            let inserted_chain: Vec<EventContainer> = Vec::new();
            if let Ok(chain_data) = self
                .resolve_chain_data(
                    &decoded.data.keys,
                    &decoded.data.chain_id,
                    decoded.data.chain_type,
                    &events,
                )
                .await
            {
                // We try to add shorter and shorter chains until we have a success
                for data in chain_data.iter() {
                    debug!("Processing company chain data with block {data:#?}");
                    // let blocks = data.iter().map(|d| d.block.clone()).collect();
                    // debug!("Processing chain data with {} blocks", blocks.len());
                    // if !data.is_empty()
                    //     && self
                    //         .processor
                    //         .process_chain_data(
                    //             &BillId::from_str(&decoded.data.chain_id)?,
                    //             blocks,
                    //             Some(BillKeys {
                    //                 public_key: decoded.data.keys.public_key.to_owned(),
                    //                 private_key: decoded.data.keys.private_key.to_owned(),
                    //             }),
                    //         )
                    //         .await
                    //         .is_ok()
                    // {
                    //     inserted_chain = data.to_owned();
                    //     break;
                    // }
                }
                // we are onboarded to the chain so store all Nostr chain data also the invalid one
                if let Err(e) = self
                    .store_events(
                        &decoded.data.chain_id,
                        decoded.data.chain_type,
                        inserted_chain,
                        &chain_data,
                    )
                    .await
                {
                    error!("Error storing chain events: {e}");
                }
            } else {
                error!("Could not extract chain data for invite event {event:?}");
            }
        } else {
            warn!("Could not decode event to ChainInvite {event:?}");
        }
        Ok(())
    }
}

impl ServiceTraitBounds for CompanyInviteEventHandler {}

impl CompanyInviteEventHandler {
    pub fn new(
        transport: Arc<dyn NotificationJsonTransportApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    ) -> Self {
        Self {
            transport,
            chain_event_store,
        }
    }

    /// Parses chain keys, resolves all Nostr events and builds Nostr chains from it.
    /// Then decrypts the payloads and parses the block contents. Returns all found chains
    /// in descending order by chain length.
    async fn resolve_chain_data(
        &self,
        keys: &ChainKeys,
        chain_id: &str,
        chain_type: BlockchainType,
        events: &[nostr_sdk::Event],
    ) -> Result<Vec<Vec<EventContainer>>> {
        let keys = BcrKeys::from_private_key(&keys.private_key)?;
        let mut chains = collect_event_chains(events, chain_id, chain_type, &keys);
        chains.sort_by_key(|v| Reverse(v.len()));
        Ok(chains)
    }

    async fn store_events(
        &self,
        chain_id: &str,
        chain_type: BlockchainType,
        inserted_chain: Vec<EventContainer>,
        chains: &[Vec<EventContainer>],
    ) -> Result<()> {
        let mut to_insert: HashMap<String, NostrChainEvent> = HashMap::new();

        // first store the inserted valid blocks
        for (idx, inserted) in inserted_chain.iter().enumerate() {
            let data = inserted.as_chain_store_event(chain_id, chain_type, idx + 1, true);
            to_insert.insert(data.event_id.to_owned(), data);
        }

        // then store all malicious or invalid blocks with their pretended block height
        for chain in chains {
            for (idx, data) in chain.iter().enumerate() {
                if !to_insert.contains_key(&data.event.id.to_string()) {
                    let data = data.as_chain_store_event(chain_id, chain_type, idx + 1, false);
                    to_insert.insert(data.event_id.to_owned(), data);
                }
            }
        }

        for (_, data) in to_insert {
            if let Err(e) = self.chain_event_store.add_chain_event(data).await {
                debug!("Could not store chain event because {e}")
            }
        }
        Ok(())
    }
}
