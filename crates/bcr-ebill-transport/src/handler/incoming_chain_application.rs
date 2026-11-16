use crate::Result;
use crate::chain_keys::ChainKeyServiceApi;
use crate::handler::{
    BillChainEventProcessorApi, CompanyChainEventProcessorApi, IdentityChainEventProcessorApi,
};
use crate::transport::{
    decrypt_or_decode_public_chain_event, root_and_reply_id, unwrap_public_chain_event,
};
use async_trait::async_trait;
use bcr_ebill_api::service::transport_service::InvalidIncomingBlock;
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_core::protocol::{BlockId, ProtocolValidationError, Sha256Hash, Timestamp};
use bcr_ebill_core::protocol::{
    blockchain::{Block, Blockchain, BlockchainType},
    event::{BillBlockEvent, CompanyBlockEvent, Event as BcrEvent, EventType, IdentityBlockEvent},
};
use bcr_ebill_persistence::NostrChainEventStoreApi;
use bcr_ebill_persistence::traits::nostr::NostrChainEvent;
use bcr_ebill_persistence::traits::propagation::IncomingChainCandidate;
use std::sync::Arc;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait IncomingChainApplicationApi: ServiceTraitBounds {
    async fn apply_verified_chain_event(
        &self,
        candidate: &IncomingChainCandidate,
    ) -> Result<IncomingChainApplyResult>;
}

pub struct IncomingChainApplication {
    chain_keys: Arc<dyn ChainKeyServiceApi>,
    bill_processor: Arc<dyn BillChainEventProcessorApi>,
    company_processor: Arc<dyn CompanyChainEventProcessorApi>,
    identity_processor: Arc<dyn IdentityChainEventProcessorApi>,
    chain_event_store: Arc<dyn NostrChainEventStoreApi>,
}

impl ServiceTraitBounds for IncomingChainApplication {}

impl IncomingChainApplication {
    pub fn new(
        chain_keys: Arc<dyn ChainKeyServiceApi>,
        bill_processor: Arc<dyn BillChainEventProcessorApi>,
        company_processor: Arc<dyn CompanyChainEventProcessorApi>,
        identity_processor: Arc<dyn IdentityChainEventProcessorApi>,
        chain_event_store: Arc<dyn NostrChainEventStoreApi>,
    ) -> Self {
        Self {
            chain_keys,
            bill_processor,
            company_processor,
            identity_processor,
            chain_event_store,
        }
    }

    async fn apply_candidate(
        &self,
        candidate: &IncomingChainCandidate,
    ) -> Result<IncomingChainApplyResult> {
        let Some(public) = unwrap_public_chain_event(&candidate.event)? else {
            return Ok(IncomingChainApplyResult::Rejected(
                "Not a public chain event".into(),
            ));
        };

        // candidate and nostr event must match
        if public.id != candidate.chain_id || public.chain_type.to_string() != candidate.chain_type
        {
            return Ok(IncomingChainApplyResult::Rejected(
                "Incoming candidate chain metadata mismatch".into(),
            ));
        }

        let keys = match self
            .chain_keys
            .get_chain_keys(&public.id, public.chain_type)
            .await
        {
            Ok(Some(keys)) => keys,
            Ok(None) => {
                return Ok(IncomingChainApplyResult::Deferred(
                    IncomingChainDependency::MissingKeys,
                ));
            }
            Err(e) => return Err(e),
        };

        let envelope =
            match decrypt_or_decode_public_chain_event(&public.payload, &Some(keys.clone())) {
                Ok(envelope) => envelope,
                Err(e) => return Ok(IncomingChainApplyResult::Rejected(e.to_string())),
            };
        let expected_type = match public.chain_type {
            BlockchainType::Bill => EventType::BillChain,
            BlockchainType::Company => EventType::CompanyChain,
            BlockchainType::Identity => EventType::IdentityChain,
        };
        if envelope.event_type != expected_type {
            return Ok(IncomingChainApplyResult::Rejected(
                "Chain event payload type mismatch".into(),
            ));
        }

        let (res, hash, height) = match public.chain_type {
            BlockchainType::Bill => {
                let decoded = match BcrEvent::<BillBlockEvent>::try_from(envelope) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        return Ok(IncomingChainApplyResult::Rejected(e.to_string()));
                    }
                };
                let data = decoded.data;
                if data.bill_id.to_string() != public.id
                    || data.block.id().inner() != data.block_height as u64
                {
                    return Ok(IncomingChainApplyResult::Rejected(
                        "Bill block metadata mismatch".into(),
                    ));
                }
                let hash = data.block.hash().clone();
                let res = self
                    .bill_processor
                    .apply_verified_block(&data.bill_id, data.block, keys)
                    .await?;
                (res, hash, data.block_height)
            }
            BlockchainType::Company => {
                let decoded = match BcrEvent::<CompanyBlockEvent>::try_from(envelope) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        return Ok(IncomingChainApplyResult::Rejected(e.to_string()));
                    }
                };
                let data = decoded.data;
                if data.node_id.to_string() != public.id
                    || data.block.id().inner() != data.block_height as u64
                {
                    return Ok(IncomingChainApplyResult::Rejected(
                        "Company block metadata mismatch".into(),
                    ));
                }
                let hash = data.block.hash().clone();
                let res = self
                    .company_processor
                    .apply_verified_block(&data.node_id, data.block, keys)
                    .await?;
                (res, hash, data.block_height)
            }
            BlockchainType::Identity => {
                let decoded = match BcrEvent::<IdentityBlockEvent>::try_from(envelope) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        return Ok(IncomingChainApplyResult::Rejected(e.to_string()));
                    }
                };
                let data = decoded.data;
                if data.node_id.to_string() != public.id
                    || data.block.id().inner() != data.block_height as u64
                {
                    return Ok(IncomingChainApplyResult::Rejected(
                        "Identity block metadata mismatch".into(),
                    ));
                }
                let hash = data.block.hash().clone();
                let res = self
                    .identity_processor
                    .apply_verified_block(&data.node_id, data.block, keys)
                    .await?;
                (res, hash, data.block_height)
            }
        };

        // if application succeeded, persist the chain event metadata
        if matches!(
            res,
            IncomingChainApplyResult::Applied | IncomingChainApplyResult::AlreadyApplied
        ) {
            self.persist_chain_event(candidate, public.chain_type, hash, height)
                .await?;
        }
        Ok(res)
    }

    async fn persist_chain_event(
        &self,
        candidate: &IncomingChainCandidate,
        chain_type: BlockchainType,
        block_hash: Sha256Hash,
        block_height: usize,
    ) -> Result<()> {
        let event = &candidate.event;
        let event_id = event.id.to_string();

        let existing = self
            .chain_event_store
            .by_event_id(&event_id)
            .await
            .map_err(|e| crate::Error::Persistence(e.to_string()))?;
        if existing.is_some() {
            return Ok(());
        }

        let (root, reply) = root_and_reply_id(event);
        self.chain_event_store
            .add_chain_event(NostrChainEvent {
                event_id: event_id.clone(),
                root_id: root.map(|id| id.to_string()).unwrap_or(event_id),
                reply_id: reply.map(|id| id.to_string()),
                author: event.pubkey.to_string(),
                chain_id: candidate.chain_id.clone(),
                chain_type,
                block_height,
                block_hash,
                received: Timestamp::now(),
                time: event.created_at.into(),
                payload: event.clone(),
            })
            .await
            .map_err(|e| crate::Error::Persistence(e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl IncomingChainApplicationApi for IncomingChainApplication {
    async fn apply_verified_chain_event(
        &self,
        candidate: &IncomingChainCandidate,
    ) -> Result<IncomingChainApplyResult> {
        self.apply_candidate(candidate).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingChainApplyResult {
    Applied,
    AlreadyApplied,
    Deferred(IncomingChainDependency),
    Rejected(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncomingChainDependency {
    MissingKeys,
    MissingPredecessor,
    ChainNotInitialized,
    ConflictingFork,
}

#[cfg(test)]
impl ServiceTraitBounds for MockIncomingChainApplicationApi {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockPosition {
    Next,
    AlreadyApplied,
    MissingPredecessor,
    ChainNotInitialized,
    ConflictingFork,
}

pub(crate) fn block_position<C: Blockchain>(chain: Option<&C>, block: &C::Block) -> BlockPosition {
    let Some(chain) = chain else {
        return if block.id() == BlockId::first() {
            BlockPosition::Next
        } else {
            BlockPosition::ChainNotInitialized
        };
    };
    if chain
        .blocks()
        .iter()
        .any(|existing| existing.id() == block.id() && existing.hash() == block.hash())
    {
        return BlockPosition::AlreadyApplied;
    }
    let tip = chain.get_latest_block();
    if block.id() <= tip.id() {
        return BlockPosition::ConflictingFork;
    }
    let next = BlockId::next_from_previous_block_id(&tip.id());
    if block.id() > next {
        return BlockPosition::MissingPredecessor;
    }
    if block.previous_hash() != tip.hash() {
        return BlockPosition::ConflictingFork;
    }
    BlockPosition::Next
}

pub(crate) fn deferred_position(position: BlockPosition) -> Option<IncomingChainApplyResult> {
    match position {
        BlockPosition::Next => None,
        BlockPosition::AlreadyApplied => Some(IncomingChainApplyResult::AlreadyApplied),
        BlockPosition::MissingPredecessor => Some(IncomingChainApplyResult::Deferred(
            IncomingChainDependency::MissingPredecessor,
        )),
        BlockPosition::ChainNotInitialized => Some(IncomingChainApplyResult::Deferred(
            IncomingChainDependency::ChainNotInitialized,
        )),
        BlockPosition::ConflictingFork => Some(IncomingChainApplyResult::Deferred(
            IncomingChainDependency::ConflictingFork,
        )),
    }
}

pub(crate) fn classify_verified_application_result(
    result: Result<()>,
) -> Result<IncomingChainApplyResult> {
    match result {
        Ok(()) => Ok(IncomingChainApplyResult::Applied),
        // invalid blocks that can't be recovered and where it makes no sense to retry
        Err(crate::Error::InvalidIncomingBlock(reason)) => {
            Ok(IncomingChainApplyResult::Rejected(reason.to_string()))
        }
        // retryable errors - network, database, crypto etc.
        Err(e) => Err(e),
    }
}

pub(crate) fn validate_incoming_block_integrity<B: Block>(block: &B) -> Result<()> {
    if !block.validate_hash() {
        return Err(InvalidIncomingBlock::InvalidHash.into());
    }
    if !block.verify() {
        return Err(InvalidIncomingBlock::InvalidSignature.into());
    }
    Ok(())
}

pub(crate) fn map_block_signer_error(
    error: bcr_ebill_core::protocol::blockchain::Error,
) -> crate::Error {
    use bcr_ebill_core::protocol::blockchain::Error as BlockError;
    match error {
        e @ BlockError::BlockSignatureDoesNotMatchSigner => {
            InvalidIncomingBlock::InvalidSigner(e.to_string()).into()
        }
        e => crate::Error::Blockchain(e.to_string()),
    }
}

/// map validation errors we can definitely say lead to a rejection
pub(crate) fn map_chain_action_validation_error(error: ProtocolValidationError) -> crate::Error {
    match error {
        e @ (ProtocolValidationError::InvalidCompanyAction
        | ProtocolValidationError::InvalidIdentityAction
        | ProtocolValidationError::InvalidIdentityProof
        | ProtocolValidationError::InvalidReferenceBlock
        | ProtocolValidationError::CallerMustBeSignatory
        | ProtocolValidationError::CallerMustBeCreator
        | ProtocolValidationError::CallerMustBeIdentifiedCreator
        | ProtocolValidationError::NotInvitedAsSignatory
        | ProtocolValidationError::NotASignatory(_)
        | ProtocolValidationError::SignatoryAlreadySignatory(_)
        | ProtocolValidationError::CantRemoveLastSignatory) => {
            InvalidIncomingBlock::InvalidAction(e.to_string()).into()
        }
        e => crate::Error::Blockchain(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_keys::ChainKeyService;
    use crate::handler::test_utils::{MockBillStore, MockCompanyStore, MockIdentityStore};
    use crate::handler::{
        MockBillChainEventProcessorApi, MockCompanyChainEventProcessorApi,
        MockIdentityChainEventProcessorApi,
    };
    use crate::test_utils::{
        MockChainKeyService, MockNostrChainEventStore, bill_id_test, bill_id_test_other2,
        empty_address, get_baseline_bill, get_baseline_identity, get_bill_keys, get_genesis_chain,
        signed_identity_proof_test, test_ts,
    };
    use bcr_common::core::BillId;
    use bcr_ebill_core::protocol::{
        blockchain::bill::{
            BillBlock, BillBlockchain,
            block::{BillParticipantBlockData, BillRequestToAcceptBlockData},
            participant::BillIdentParticipant,
        },
        constants::ACCEPT_DEADLINE_SECONDS,
        event::EventEnvelope,
    };
    use nostr::{event::FinalizeEvent, key::Keys};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use url::Url;

    fn chain_and_second_block() -> (BillBlockchain, BillBlock) {
        let keys = get_bill_keys();
        let bill_id = BillId::new(keys.pub_key(), bitcoin::Network::Testnet);
        let chain = get_genesis_chain(Some(get_baseline_bill(&bill_id)));
        let payer = BillIdentParticipant::new(get_baseline_identity().identity).unwrap();
        let ts = chain.get_latest_block().timestamp + 1000;
        let block = BillBlock::create_block_for_request_to_accept(
            bill_id,
            chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(payer.into()),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(empty_address()),
                signer_identity_proof: Some(signed_identity_proof_test().into()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &keys,
            None,
            &keys,
            ts,
        )
        .unwrap();
        (chain, block)
    }

    fn bill_candidate(payload_bill_id: BillId) -> IncomingChainCandidate {
        let chain = get_genesis_chain(None);
        let block = chain.get_first_block().clone();
        let envelope: EventEnvelope = BcrEvent::new_bill_chain(BillBlockEvent {
            bill_id: payload_bill_id,
            block_height: block.id.inner() as usize,
            block,
        })
        .try_into()
        .unwrap();
        let event = crate::transport::create_public_chain_event(
            &bill_id_test().to_string(),
            envelope,
            test_ts(),
            BlockchainType::Bill,
            None,
            None,
        )
        .unwrap()
        .finalize(&Keys::generate())
        .unwrap();
        IncomingChainCandidate {
            event,
            chain_type: "bill".into(),
            chain_id: bill_id_test().to_string(),
            relays: vec![Url::parse("wss://r1.example").unwrap()],
            required_relays: 1,
            attempts: 0,
            application_attempts: 0,
        }
    }

    fn application_with_mocks(
        keys: MockChainKeyService,
        bill_processor: MockBillChainEventProcessorApi,
        events: MockNostrChainEventStore,
    ) -> IncomingChainApplication {
        IncomingChainApplication::new(
            Arc::new(keys),
            Arc::new(bill_processor),
            Arc::new(MockCompanyChainEventProcessorApi::new()),
            Arc::new(MockIdentityChainEventProcessorApi::new()),
            Arc::new(events),
        )
    }

    #[test]
    fn missing_chain_genesis_is_next() {
        let (chain, _) = chain_and_second_block();
        let genesis = chain.get_first_block();
        assert_eq!(
            block_position::<BillBlockchain>(None, genesis),
            BlockPosition::Next,
        );
    }

    #[test]
    fn missing_chain_non_genesis_is_not_ready() {
        let (_, block2) = chain_and_second_block();
        assert_eq!(
            block_position::<BillBlockchain>(None, &block2),
            BlockPosition::ChainNotInitialized,
        );
    }

    #[test]
    fn previously_applied_block_is_recognized_below_tip() {
        let (mut chain, block2) = chain_and_second_block();
        let genesis = chain.get_first_block().clone();
        assert!(chain.try_add_block(block2));
        assert_eq!(
            block_position(Some(&chain), &genesis),
            BlockPosition::AlreadyApplied,
        );
    }

    #[test]
    fn same_height_different_hash_is_a_fork() {
        let (mut chain, block2) = chain_and_second_block();
        let mut fork = block2.clone();
        fork.hash = chain.get_first_block().hash.clone();
        assert!(chain.try_add_block(block2));
        assert_eq!(
            block_position(Some(&chain), &fork),
            BlockPosition::ConflictingFork,
        );
    }

    #[test]
    fn block_two_heights_ahead_is_missing_predecessor() {
        let (chain, mut block3) = chain_and_second_block();
        block3.id = BlockId::next_from_previous_block_id(&block3.id);
        assert_eq!(
            block_position(Some(&chain), &block3),
            BlockPosition::MissingPredecessor,
        );
    }

    #[test]
    fn next_height_with_wrong_parent_hash_is_a_fork() {
        let (chain, mut block2) = chain_and_second_block();
        block2.previous_hash = block2.hash.clone();
        assert_ne!(block2.previous_hash, chain.get_latest_block().hash,);
        assert_eq!(
            block_position(Some(&chain), &block2),
            BlockPosition::ConflictingFork,
        );
    }

    #[tokio::test]
    async fn key_store_error_is_not_treated_as_missing_keys() {
        let mut bill_store = MockBillStore::new();
        bill_store.expect_get_keys().once().returning(|_| {
            Err(bcr_ebill_persistence::Error::InvalidData(
                "simulated database failure".into(),
            ))
        });
        let service = ChainKeyService::new(
            Arc::new(bill_store),
            Arc::new(MockCompanyStore::new()),
            Arc::new(MockIdentityStore::new()),
        );
        let result = service
            .get_chain_keys(&bill_id_test().to_string(), BlockchainType::Bill)
            .await;
        assert!(matches!(result, Err(crate::Error::Persistence(_)),));
    }

    #[tokio::test]
    async fn application_does_not_defer_database_error_as_missing_keys() {
        let candidate = bill_candidate(bill_id_test());
        let mut keys = MockChainKeyService::new();
        keys.expect_get_chain_keys()
            .once()
            .returning(|_, _| Err(crate::Error::Persistence("database timeout".into())));
        let mut processor = MockBillChainEventProcessorApi::new();
        processor.expect_apply_verified_block().never();
        let application = application_with_mocks(keys, processor, MockNostrChainEventStore::new());
        let result = application.apply_verified_chain_event(&candidate).await;
        assert!(matches!(
            result,
            Err(crate::Error::Persistence(message))
                if message.contains("database timeout")
        ));
    }

    #[tokio::test]
    async fn metadata_failure_is_recoverable_on_retry() {
        let candidate = bill_candidate(bill_id_test());

        let mut keys = MockChainKeyService::new();
        keys.expect_get_chain_keys()
            .times(2)
            .returning(|_, _| Ok(Some(get_bill_keys())));
        let processor_calls = Arc::new(AtomicUsize::new(0));
        let calls = processor_calls.clone();
        let mut processor = MockBillChainEventProcessorApi::new();
        processor
            .expect_apply_verified_block()
            .times(2)
            .returning(move |_, _, _| {
                let attempt = calls.fetch_add(1, Ordering::SeqCst);

                if attempt == 0 {
                    Ok(IncomingChainApplyResult::Applied)
                } else {
                    Ok(IncomingChainApplyResult::AlreadyApplied)
                }
            });

        let mut events = MockNostrChainEventStore::new();
        events.expect_by_event_id().times(2).returning(|_| Ok(None));

        let insert_calls = Arc::new(AtomicUsize::new(0));
        let calls = insert_calls.clone();
        events
            .expect_add_chain_event()
            .times(2)
            .returning(move |_| {
                let attempt = calls.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    Err(bcr_ebill_persistence::Error::InvalidData(
                        "simulated metadata insert failure".into(),
                    ))
                } else {
                    Ok(())
                }
            });

        let application = application_with_mocks(keys, processor, events);

        // blockchain applied, metadata insert failed
        let first = application.apply_verified_chain_event(&candidate).await;
        assert!(matches!(first, Err(crate::Error::Persistence(_)),));

        // next application attempt sees existing block, then retries and inserts metadata
        let second = application
            .apply_verified_chain_event(&candidate)
            .await
            .unwrap();
        assert_eq!(second, IncomingChainApplyResult::AlreadyApplied,);
        assert_eq!(processor_calls.load(Ordering::SeqCst), 2,);
        assert_eq!(insert_calls.load(Ordering::SeqCst), 2,);
    }

    #[tokio::test]
    async fn payload_chain_id_mismatch_is_rejected_without_processing() {
        let candidate = bill_candidate(bill_id_test_other2());
        let mut keys = MockChainKeyService::new();
        keys.expect_get_chain_keys()
            .once()
            .returning(|_, _| Ok(Some(get_bill_keys())));
        let mut processor = MockBillChainEventProcessorApi::new();
        processor.expect_apply_verified_block().never();
        let application = application_with_mocks(keys, processor, MockNostrChainEventStore::new());
        let result = application
            .apply_verified_chain_event(&candidate)
            .await
            .unwrap();
        assert_eq!(
            result,
            IncomingChainApplyResult::Rejected("Bill block metadata mismatch".into(),),
        );
    }

    #[test]
    fn invalid_block_integrity_is_detected() {
        let (chain, block) = chain_and_second_block();
        assert!(validate_incoming_block_integrity(&block).is_ok());
        let mut bad_hash = block.clone();
        bad_hash.hash = chain.get_first_block().hash.clone();
        assert!(matches!(
            validate_incoming_block_integrity(&bad_hash),
            Err(crate::Error::InvalidIncomingBlock(
                InvalidIncomingBlock::InvalidHash
            ))
        ));
        let mut bad_signature = block.clone();
        bad_signature.signature = chain.get_first_block().signature.clone();
        assert!(bad_signature.validate_hash());
        assert!(matches!(
            validate_incoming_block_integrity(&bad_signature),
            Err(crate::Error::InvalidIncomingBlock(
                InvalidIncomingBlock::InvalidSignature
            ))
        ));
    }

    #[test]
    fn classify_only_deterministic_invalid_blocks_as_rejected() {
        let rejected =
            classify_verified_application_result(Err(InvalidIncomingBlock::InvalidHash.into()))
                .unwrap();
        assert_eq!(
            rejected,
            IncomingChainApplyResult::Rejected(InvalidIncomingBlock::InvalidHash.to_string(),)
        );
        // generic blockchain error remains retryable
        let blockchain = classify_verified_application_result(Err(crate::Error::Blockchain(
            "could not decrypt block".into(),
        )));
        assert!(matches!(blockchain, Err(crate::Error::Blockchain(_))));
        // persistence errors remain retryable
        let persistence = classify_verified_application_result(Err(crate::Error::Persistence(
            "database unavailable".into(),
        )));
        assert!(matches!(persistence, Err(crate::Error::Persistence(_))));
    }

    #[test]
    fn classify_only_explicit_signer_mismatch_as_invalid() {
        let invalid = map_block_signer_error(
            bcr_ebill_core::protocol::blockchain::Error::BlockSignatureDoesNotMatchSigner,
        );
        assert!(matches!(
            invalid,
            crate::Error::InvalidIncomingBlock(InvalidIncomingBlock::InvalidSigner(_))
        ));
        let ambiguous =
            map_block_signer_error(bcr_ebill_core::protocol::blockchain::Error::BlockInvalid);
        assert!(matches!(ambiguous, crate::Error::Blockchain(_)));
    }

    #[test]
    fn classify_pure_action_errors_regression_test() {
        let invalid_actions = [
            ProtocolValidationError::InvalidCompanyAction,
            ProtocolValidationError::InvalidIdentityAction,
            ProtocolValidationError::InvalidIdentityProof,
            ProtocolValidationError::CallerMustBeSignatory,
            ProtocolValidationError::CallerMustBeCreator,
            ProtocolValidationError::NotASignatory("removed-node".into()),
        ];
        for error in invalid_actions {
            let result = map_chain_action_validation_error(error);
            assert!(matches!(
                result,
                crate::Error::InvalidIncomingBlock(InvalidIncomingBlock::InvalidAction(_))
            ));
        }
        let ambiguous = map_chain_action_validation_error(ProtocolValidationError::Blockchain(
            "could not decrypt chain data".into(),
        ));
        assert!(matches!(ambiguous, crate::Error::Blockchain(_)));
    }
}
