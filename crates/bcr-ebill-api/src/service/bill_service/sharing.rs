use bcr_ebill_core::{
    bill::{BillId, BillToShareWithExternalParty},
    util::BcrKeys,
};
use secp256k1::PublicKey;

use crate::util;

use super::{BillService, Result};

impl BillService {
    #[allow(dead_code)]
    /// Creates a payload of a bill, including the encrypted and plaintext block data, encrypted
    /// with the pub key of an external party, and signed by the sharer of the data, so the receiver
    /// can fully validate the bill
    pub(super) async fn share_bill_with_external_party(
        &self,
        bill_id: &BillId,
        external_party_pub_key: &PublicKey,
        sharer_keys: &BcrKeys,
        file_urls: &[url::Url],
    ) -> Result<BillToShareWithExternalParty> {
        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;

        let chain_with_plaintext = chain.get_chain_with_plaintext_block_data(&bill_keys)?;
        let serialized = borsh::to_vec(&chain_with_plaintext)?;
        let encrypted = util::crypto::encrypt_ecies(&serialized, external_party_pub_key)?;
        let encoded = util::base58_encode(&encrypted);

        let hash = util::sha256_hash(&serialized);
        let signature = util::crypto::signature(&hash, &sharer_keys.get_private_key())?;

        let result = BillToShareWithExternalParty {
            bill_id: bill_id.to_owned(),
            data: encoded,
            file_urls: file_urls.to_owned(),
            hash,
            signature,
            receiver: external_party_pub_key.to_owned(),
        };
        Ok(result)
    }
}

#[cfg(test)]
pub mod tests {
    use bcr_ebill_core::blockchain::{
        Blockchain,
        bill::{
            BillBlock, BillBlockchain, BillOpCode,
            block::{BillAcceptBlockData, BillIssueBlockData},
            chain::BillBlockPlaintextWrapper,
        },
    };

    use crate::{
        service::bill_service::test_utils::{
            accept_block, get_baseline_bill, get_baseline_identity, get_ctx, get_genesis_chain,
            get_service,
        },
        tests::tests::{bill_id_test, bill_identified_participant_only_node_id, node_id_test},
    };

    use super::*;

    #[tokio::test]
    async fn test_share_bill_with_external_party() {
        let external_party_keys = BcrKeys::new();
        let external_party_pub_key = external_party_keys.pub_key();
        let sharer_keys = BcrKeys::new();

        let mut ctx = get_ctx();
        let identity = get_baseline_identity();
        let mut bill = get_baseline_bill(&bill_id_test());
        let bill_id = bill.id.clone();
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();

        ctx.bill_blockchain_store
            .expect_get_chain()
            .returning(move |_| {
                let mut chain = get_genesis_chain(Some(bill.clone()));
                chain.try_add_block(accept_block(&bill.id, chain.get_latest_block()));
                Ok(chain)
            });

        let service = get_service(ctx);

        let result = service
            .share_bill_with_external_party(&bill_id, &external_party_pub_key, &sharer_keys, &[])
            .await;
        assert!(result.is_ok());

        // Receiver side
        let unwrapped = result.unwrap().clone();
        assert_eq!(unwrapped.bill_id, bill_id);
        assert_eq!(unwrapped.receiver, external_party_pub_key);
        let data = unwrapped.data;
        let hash = unwrapped.hash;
        let signature = unwrapped.signature;
        // receiver can check that req was signed by the sharer
        assert!(util::crypto::verify(&hash, &signature, &sharer_keys.pub_key()).unwrap());
        let decoded = util::base58_decode(&data).unwrap();
        // receiver can decrypt it
        let decrypted =
            util::crypto::decrypt_ecies(&decoded, &external_party_keys.get_private_key()).unwrap();
        // receiver can check that hash matches the data
        assert_eq!(hash, util::sha256_hash(&decrypted));
        let deserialized: Vec<BillBlockPlaintextWrapper> = borsh::from_slice(&decrypted).unwrap();
        // receiver can check that plaintext hashes match
        for block_wrapper in deserialized.iter() {
            assert_eq!(
                block_wrapper.block.plaintext_hash,
                util::sha256_hash(&block_wrapper.plaintext_data_bytes)
            )
        }
        // receiver can check that chain is valid
        BillBlockchain::new_from_blocks(
            deserialized
                .iter()
                .map(|wrapper| wrapper.block.to_owned())
                .collect::<Vec<BillBlock>>(),
        )
        .unwrap();
        // receiver can access actual block data
        let issue = deserialized[0].clone();
        assert!(matches!(issue.block.op_code, BillOpCode::Issue));
        let plaintext_issue: BillIssueBlockData =
            borsh::from_slice(&issue.plaintext_data_bytes).unwrap();
        assert_eq!(plaintext_issue.id, bill_id);
        assert_eq!(plaintext_issue.drawee.node_id, drawee_node_id);

        let accept = deserialized[1].clone();
        assert!(matches!(accept.block.op_code, BillOpCode::Accept));
        let plaintext_accept: BillAcceptBlockData =
            borsh::from_slice(&accept.plaintext_data_bytes).unwrap();
        assert_eq!(plaintext_accept.accepter.node_id, node_id_test());
    }
}
