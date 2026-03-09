use std::collections::HashMap;

use super::Result;
use super::block::{CompanyBlock, CompanyCreateBlockData};
use super::{Block, Blockchain, CompanyOpCode};
use crate::protocol::Timestamp;
use crate::protocol::blockchain::company::CompanyBlockPayload;
use crate::protocol::blockchain::company::block::{
    CompanyIdentityProofBlockData, CompanyInviteSignatoryBlockData,
    CompanyRemoveSignatoryBlockData, CompanySignCompanyBillBlockData,
    CompanySignatoryAcceptInviteBlockData, CompanySignatoryRejectInviteBlockData,
    CompanyUpdateBlockData,
};
use crate::protocol::blockchain::{Error, borsh_to_json_value};
use crate::protocol::crypto::BcrKeys;
use crate::protocol::{BlockId, Sha256Hash};
use bcr_common::core::NodeId;
use borsh_derive::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CompanyBlockchain {
    blocks: Vec<CompanyBlock>,
}

impl Blockchain for CompanyBlockchain {
    type Block = CompanyBlock;

    fn blocks(&self) -> &Vec<Self::Block> {
        &self.blocks
    }

    fn blocks_mut(&mut self) -> &mut Vec<Self::Block> {
        &mut self.blocks
    }
}

impl CompanyBlockchain {
    /// Creates a new company chain
    pub fn new(
        company: &CompanyCreateBlockData,
        identity_keys: &BcrKeys,
        company_keys: &BcrKeys,
        timestamp: Timestamp,
    ) -> Result<Self> {
        let genesis_hash = Sha256Hash::from_bytes(company.id.to_string().as_bytes());

        let first_block = CompanyBlock::create_block_for_create(
            company.id.clone(),
            genesis_hash,
            company,
            identity_keys,
            company_keys,
            timestamp,
        )?;

        Ok(Self {
            blocks: vec![first_block],
        })
    }

    /// Creates a company chain from a vec of blocks
    pub fn new_from_blocks(blocks_to_add: Vec<CompanyBlock>) -> Result<Self> {
        match blocks_to_add.first() {
            None => Err(super::super::Error::BlockchainInvalid),
            Some(first) => {
                if !first.verify() || !first.validate_hash() {
                    return Err(super::super::Error::BlockchainInvalid);
                }

                let chain = Self {
                    blocks: blocks_to_add,
                };

                if !chain.is_chain_valid() {
                    return Err(super::super::Error::BlockchainInvalid);
                }

                Ok(chain)
            }
        }
    }

    pub fn get_chain_with_plaintext_block_data(
        &self,
        company_keys: &BcrKeys,
    ) -> Result<Vec<CompanyBlockPlaintextWrapper>> {
        let mut result = Vec::with_capacity(self.blocks().len());
        for block in self.blocks.iter() {
            let plaintext_data_bytes = match block.op_code() {
                CompanyOpCode::Create => block.get_decrypted_block_bytes(company_keys)?,
                CompanyOpCode::Update => block.get_decrypted_block_bytes(company_keys)?,
                CompanyOpCode::InviteSignatory => block.get_decrypted_block_bytes(company_keys)?,
                CompanyOpCode::SignatoryAcceptInvite => {
                    block.get_decrypted_block_bytes(company_keys)?
                }
                CompanyOpCode::SignatoryRejectInvite => {
                    block.get_decrypted_block_bytes(company_keys)?
                }
                CompanyOpCode::RemoveSignatory => block.get_decrypted_block_bytes(company_keys)?,
                CompanyOpCode::SignCompanyBill => block.get_decrypted_block_bytes(company_keys)?,
                CompanyOpCode::IdentityProof => block.get_decrypted_block_bytes(company_keys)?,
            };

            if block.plaintext_hash != Sha256Hash::from_bytes(&plaintext_data_bytes) {
                return Err(Error::BlockInvalid);
            }

            result.push(CompanyBlockPlaintextWrapper {
                block: block.clone(),
                plaintext_data_bytes,
            });
        }

        // Validate the chain from the wrapper
        CompanyBlockchain::new_from_blocks(
            result
                .iter()
                .map(|wrapper| wrapper.block.to_owned())
                .collect::<Vec<CompanyBlock>>(),
        )?;

        Ok(result)
    }

    // Checks if the given node id was the creator of the company
    pub fn is_creator(&self, node_id: &NodeId, company_keys: &BcrKeys) -> Result<bool> {
        if let CompanyBlockPayload::Create(block_data) =
            self.get_first_block().get_block_data(company_keys)?
            && &block_data.creator == node_id
        {
            return Ok(true);
        }
        Ok(false)
    }

    // Checks if the given node id is currently invited in this company
    pub fn is_invited(&self, node_id: &NodeId, company_keys: &BcrKeys) -> Result<bool> {
        // find last invite block for node id
        let mut last_invite_for_node_id = None;
        for block in self.blocks().iter().rev() {
            if let CompanyBlockPayload::InviteSignatory(block_data) =
                block.get_block_data(company_keys)?
                && &block_data.invitee == node_id
            {
                last_invite_for_node_id = Some(block);
                break;
            }
        }

        match last_invite_for_node_id {
            // node id was invited, check that it wasn't accepted, or removed afterwards
            Some(b) => {
                let block_id = b.id();
                // check it wasn't accepted afterwards
                for block in self.blocks().iter().rev() {
                    if block.id() > block_id
                        && &block.signatory_node_id == node_id
                        && matches!(block.op_code(), CompanyOpCode::SignatoryAcceptInvite)
                    {
                        return Ok(false);
                    }
                }

                // check it wasn't rejected afterwards
                for block in self.blocks().iter().rev() {
                    if block.id() > block_id
                        && &block.signatory_node_id == node_id
                        && matches!(block.op_code(), CompanyOpCode::SignatoryRejectInvite)
                    {
                        return Ok(false);
                    }
                }

                // check it wasn't removed afterwards
                if self.was_removed_after_block(node_id, &block_id, company_keys)? {
                    return Ok(false);
                }
                Ok(true)
            }
            // node id was never invited
            None => Ok(false),
        }
    }

    // Check that the invitee was either never invited, rejected after last invite, or was removed after last invite
    pub fn can_be_invited(&self, invitee: &NodeId, company_keys: &BcrKeys) -> Result<bool> {
        // find last invite block for node id
        let mut last_invite_for_node_id = None;
        for block in self.blocks().iter().rev() {
            if let CompanyBlockPayload::InviteSignatory(block_data) =
                block.get_block_data(company_keys)?
                && &block_data.invitee == invitee
            {
                last_invite_for_node_id = Some(block);
                break;
            }
        }

        match last_invite_for_node_id {
            // node id was invited, check that it didn't reject, or wasn't removed after
            Some(b) => {
                let block_id = b.id();
                // check it didn't reject afterwards
                for block in self.blocks().iter().rev() {
                    if block.id() > block_id
                        && &block.signatory_node_id == invitee
                        && matches!(block.op_code(), CompanyOpCode::SignatoryRejectInvite)
                    {
                        // Rejected last invite - can be invited
                        return Ok(true);
                    }
                }

                // check it wasn't removed afterwards
                if self.was_removed_after_block(invitee, &block_id, company_keys)? {
                    // Was removed after last invite - can be invited
                    return Ok(true);
                }
                Ok(false)
            }
            // node id was never invited - check if they are the creator
            None => {
                if self.is_creator(invitee, company_keys)? {
                    // check it wasn't removed afterwards
                    if self.was_removed_after_block(invitee, &BlockId::first(), company_keys)? {
                        // Was removed - can be invited
                        return Ok(true);
                    }
                    return Ok(false);
                }
                // not invited and not creator - can be invited
                Ok(true)
            }
        }
    }

    // Returns the current number of authorized signers
    pub fn num_authorized_signers(&self, company_keys: &BcrKeys) -> Result<usize> {
        // collect unique signatories with their latest block id doing an identity proof (means they were still a signatory)
        let mut signers = HashMap::new();
        for block in self.blocks().iter() {
            if matches!(block.op_code(), CompanyOpCode::IdentityProof) {
                signers.insert(block.signatory_node_id.clone(), block.id());
            }
        }

        // look at all removal blocks in reverse
        // for each node id, check if it was removed after the block id - if yes, remove from set
        for block in self.blocks().iter().rev() {
            if let CompanyBlockPayload::RemoveSignatory(block_data) =
                block.get_block_data(company_keys)?
            {
                let block_id = block.id();
                // if it was removed after the last identity proof block - the signer is removed
                if signers
                    .get(&block_data.removee)
                    .is_some_and(|&v| block_id > v)
                {
                    signers.remove(&block_data.removee);
                }
            }
        }
        // the remaining signers are the number of currently authorized signers
        Ok(signers.len())
    }

    // Checks if the given removee can be removed
    pub fn can_be_removed(&self, removee: &NodeId, company_keys: &BcrKeys) -> Result<bool> {
        // find last invite block for removee
        let mut last_invite_for_node_id = None;
        for block in self.blocks().iter().rev() {
            if let CompanyBlockPayload::InviteSignatory(block_data) =
                block.get_block_data(company_keys)?
                && &block_data.invitee == removee
            {
                last_invite_for_node_id = Some(block);
                break;
            }
        }

        match last_invite_for_node_id {
            // invited
            Some(b) => {
                let block_id = b.id();
                // check it wasn't removed afterwards
                if self.was_removed_after_block(removee, &block_id, company_keys)? {
                    // Was removed after last invite - can't be removed again
                    return Ok(false);
                }
                Ok(true)
            }
            // node id was never invited - check if they are the creator
            None => {
                if self.is_creator(removee, company_keys)? {
                    // check it wasn't removed afterwards
                    if self.was_removed_after_block(removee, &BlockId::first(), company_keys)? {
                        // Was removed - can't be removed
                        return Ok(false);
                    }
                    return Ok(true);
                }
                // not invited and not creator - can't be removed
                Ok(false)
            }
        }
    }

    // Checks if the given node_id is an accepted, but not identified signatory in this company
    pub fn is_accepted_but_not_identified_signatory(
        &self,
        node_id: &NodeId,
        company_keys: &BcrKeys,
    ) -> Result<bool> {
        // find the latest accept block for the given node id
        let mut last_accept_for_node_id = None;
        for block in self.blocks().iter().rev() {
            if &block.signatory_node_id == node_id
                && matches!(block.op_code(), CompanyOpCode::SignatoryAcceptInvite)
            {
                last_accept_for_node_id = Some(block);
                break;
            }
        }

        match last_accept_for_node_id {
            // node id was an accepted signatory
            Some(b) => {
                let block_id = b.id();
                // check it wasn't identified afterwards
                for block in self.blocks().iter().rev() {
                    if block.id() > block_id
                        && &block.signatory_node_id == node_id
                        && matches!(block.op_code(), CompanyOpCode::IdentityProof)
                    {
                        return Ok(false);
                    }
                }

                // check it wasn't removed afterwards
                if self.was_removed_after_block(node_id, &block_id, company_keys)? {
                    return Ok(false);
                }
                Ok(true)
            }
            // node id was never accepted - check if they are the creator
            None => {
                if self.is_creator(node_id, company_keys)? {
                    // check it wasn't removed afterwards
                    if self.was_removed_after_block(node_id, &BlockId::first(), company_keys)? {
                        return Ok(false);
                    }
                    return Ok(true);
                }
                // not accepted and not creator
                Ok(false)
            }
        }
    }

    // Checks if the given node_id is an authorized signatory in this company
    pub fn is_authorized_signatory(
        &self,
        node_id: &NodeId,
        company_keys: &BcrKeys,
    ) -> Result<bool> {
        // find the latest identity proof block for the given node id
        let mut last_identity_proof_for_node_id = None;
        for block in self.blocks().iter().rev() {
            if &block.signatory_node_id == node_id
                && matches!(block.op_code(), CompanyOpCode::IdentityProof)
            {
                last_identity_proof_for_node_id = Some(block);
                break;
            }
        }

        match last_identity_proof_for_node_id {
            // node id was a confirmed signatory
            Some(b) => {
                let block_id = b.id();
                // check it wasn't removed afterwards
                if self.was_removed_after_block(node_id, &block_id, company_keys)? {
                    return Ok(false);
                }
                Ok(true)
            }
            // node id was never a confirmed signatory
            None => Ok(false),
        }
    }

    // check if node id was removed after the given block
    fn was_removed_after_block(
        &self,
        node_id: &NodeId,
        block_id: &BlockId,
        company_keys: &BcrKeys,
    ) -> Result<bool> {
        for block in self.blocks().iter().rev() {
            if &block.id() > block_id
                && let CompanyBlockPayload::RemoveSignatory(block_data) =
                    block.get_block_data(company_keys)?
            {
                // node id was removed after block id
                if &block_data.removee == node_id {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct CompanyBlockPlaintextWrapper {
    pub block: CompanyBlock,
    pub plaintext_data_bytes: Vec<u8>,
}

impl CompanyBlockPlaintextWrapper {
    /// This is only used for dev mode
    pub fn to_json_text(&self) -> Result<String> {
        let mut serialized =
            serde_json::to_value(&self.block).map_err(|e| Error::JSON(e.to_string()))?;

        let block_data: serde_json::Value = match self.block.op_code() {
            CompanyOpCode::Create => {
                borsh_to_json_value::<CompanyCreateBlockData>(&self.plaintext_data_bytes)?
            }
            CompanyOpCode::Update => {
                borsh_to_json_value::<CompanyUpdateBlockData>(&self.plaintext_data_bytes)?
            }
            CompanyOpCode::InviteSignatory => {
                borsh_to_json_value::<CompanyInviteSignatoryBlockData>(&self.plaintext_data_bytes)?
            }
            CompanyOpCode::SignatoryAcceptInvite => borsh_to_json_value::<
                CompanySignatoryAcceptInviteBlockData,
            >(&self.plaintext_data_bytes)?,
            CompanyOpCode::SignatoryRejectInvite => borsh_to_json_value::<
                CompanySignatoryRejectInviteBlockData,
            >(&self.plaintext_data_bytes)?,
            CompanyOpCode::RemoveSignatory => {
                borsh_to_json_value::<CompanyRemoveSignatoryBlockData>(&self.plaintext_data_bytes)?
            }
            CompanyOpCode::SignCompanyBill => {
                borsh_to_json_value::<CompanySignCompanyBillBlockData>(&self.plaintext_data_bytes)?
            }
            CompanyOpCode::IdentityProof => {
                borsh_to_json_value::<CompanyIdentityProofBlockData>(&self.plaintext_data_bytes)?
            }
        };

        if let Some(obj) = serialized.as_object_mut() {
            obj.insert("data".to_string(), block_data);
        } else {
            return Err(Error::JSON(
                "Block didn't serialize to JSON object".to_string(),
            ));
        }
        serde_json::to_string(&serialized).map_err(|e| Error::JSON(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use bcr_common::core::NodeId;

    use super::*;
    use crate::protocol::{
        Address, BlockId, City, Country, Date, EditOptionalFieldMode, Email, Identification, Name,
        Zip,
        blockchain::{
            bill::BillOpCode,
            company::block::{
                CompanyIdentityProofBlockData, CompanyInviteSignatoryBlockData,
                CompanyRemoveSignatoryBlockData, CompanySignCompanyBillBlockData,
                CompanySignatoryAcceptInviteBlockData, CompanySignatoryRejectInviteBlockData,
                CompanyUpdateBlockData, SignatoryType,
            },
        },
        tests::tests::{
            bill_id_test, node_id_test, node_id_test_other, private_key_test,
            signed_identity_proof_test, test_ts, valid_address,
        },
    };

    fn get_baseline_company_data() -> (NodeId, (CompanyCreateBlockData, BcrKeys)) {
        (
            node_id_test(),
            (
                CompanyCreateBlockData {
                    id: node_id_test(),
                    name: Name::new("some_name").unwrap(),
                    country_of_registration: Some(Country::AT),
                    city_of_registration: Some(City::new("Vienna").unwrap()),
                    postal_address: valid_address(),
                    email: Email::new("company@example.com").unwrap(),
                    registration_number: Some(Identification::new("some_number").unwrap()),
                    registration_date: Some(Date::new("2012-01-01").unwrap()),
                    proof_of_registration_file: None,
                    logo_file: None,
                    creation_time: test_ts(),
                    creator: node_id_test(),
                },
                BcrKeys::from_private_key(&private_key_test()),
            ),
        )
    }

    #[test]
    fn test_plaintext_hash() {
        let (_id, (company, company_keys)) = get_baseline_company_data();

        let chain = CompanyBlockchain::new(
            &company,
            &BcrKeys::from_private_key(&private_key_test()),
            &company_keys,
            test_ts(),
        );
        assert!(chain.is_ok());
        assert!(chain.as_ref().unwrap().is_chain_valid());
        assert!(
            chain.as_ref().unwrap().blocks()[0]
                .validate_plaintext_hash(&company_keys.get_private_key())
        );
    }

    #[test]
    fn create_and_check_validity() {
        let (_id, (company, company_keys)) = get_baseline_company_data();

        let chain = CompanyBlockchain::new(
            &company,
            &BcrKeys::from_private_key(&private_key_test()),
            &company_keys,
            test_ts(),
        );
        assert!(chain.is_ok());
        assert!(chain.as_ref().unwrap().is_chain_valid());
    }

    #[test]
    fn multi_block() {
        let (id, (company, company_keys)) = get_baseline_company_data();
        let identity_keys = BcrKeys::from_private_key(&private_key_test());

        let chain = CompanyBlockchain::new(&company, &identity_keys, &company_keys, test_ts());
        assert!(chain.is_ok());
        assert!(chain.as_ref().unwrap().is_chain_valid());

        let mut chain = chain.unwrap();
        let update_block = CompanyBlock::create_block_for_update(
            id.clone(),
            chain.get_latest_block(),
            &CompanyUpdateBlockData {
                name: Some(Name::new("new_name").unwrap()),
                email: None,
                country: Some(Country::AT),
                city: Some(City::new("Vienna").unwrap()),
                zip: EditOptionalFieldMode::Set(Zip::new("1010").unwrap()),
                address: Some(Address::new("Kärntner Straße 1").unwrap()),
                country_of_registration: EditOptionalFieldMode::Ignore,
                city_of_registration: EditOptionalFieldMode::Ignore,
                registration_number: EditOptionalFieldMode::Ignore,
                registration_date: EditOptionalFieldMode::Ignore,
                logo_file: EditOptionalFieldMode::Ignore,
                proof_of_registration_file: EditOptionalFieldMode::Ignore,
            },
            &identity_keys,
            &company_keys,
            test_ts() + 1,
        );
        assert!(update_block.is_ok());
        chain.try_add_block(update_block.unwrap());

        let bill_block = CompanyBlock::create_block_for_sign_company_bill(
            id.clone(),
            chain.get_latest_block(),
            &CompanySignCompanyBillBlockData {
                bill_id: bill_id_test(),
                block_id: BlockId::first(),
                block_hash: Sha256Hash::new("some hash"),
                operation: BillOpCode::Issue,
                bill_key: Some(private_key_test()),
            },
            &identity_keys,
            &company_keys,
            test_ts() + 2,
        );
        assert!(bill_block.is_ok());
        chain.try_add_block(bill_block.unwrap());

        let invite_signatory_block = CompanyBlock::create_block_for_invite_signatory(
            id.clone(),
            chain.get_latest_block(),
            &CompanyInviteSignatoryBlockData {
                invitee: node_id_test(),
                inviter: node_id_test_other(),
                t: SignatoryType::Solo,
            },
            &identity_keys,
            &company_keys,
            &node_id_test().pub_key(),
            test_ts() + 3,
        );
        assert!(invite_signatory_block.is_ok());
        chain.try_add_block(invite_signatory_block.unwrap());

        let accept_invitation_block = CompanyBlock::create_block_for_accept_signatory_invite(
            id.clone(),
            chain.get_latest_block(),
            &CompanySignatoryAcceptInviteBlockData {
                accepter: node_id_test(),
            },
            &identity_keys,
            &company_keys,
            test_ts() + 4,
        );
        assert!(accept_invitation_block.is_ok());
        chain.try_add_block(accept_invitation_block.unwrap());

        let reject_invitation_block = CompanyBlock::create_block_for_reject_signatory_invite(
            id.clone(),
            chain.get_latest_block(),
            &CompanySignatoryRejectInviteBlockData {
                rejecter: node_id_test(),
            },
            &identity_keys,
            &company_keys,
            test_ts() + 5,
        );
        assert!(reject_invitation_block.is_ok());
        chain.try_add_block(reject_invitation_block.unwrap());

        let remove_signatory_block = CompanyBlock::create_block_for_remove_signatory(
            id.clone(),
            chain.get_latest_block(),
            &CompanyRemoveSignatoryBlockData {
                removee: node_id_test(),
                remover: node_id_test_other(),
            },
            &identity_keys,
            &company_keys,
            test_ts() + 6,
        );
        assert!(remove_signatory_block.is_ok());
        chain.try_add_block(remove_signatory_block.unwrap());

        let test_signed_identity = signed_identity_proof_test();
        let identity_proof_block = CompanyBlock::create_block_for_identity_proof(
            id.clone(),
            chain.get_latest_block(),
            &CompanyIdentityProofBlockData {
                proof: test_signed_identity.0,
                data: test_signed_identity.1,
                reference_block: None,
            },
            &identity_keys,
            &company_keys,
            test_ts() + 7,
        );
        assert!(identity_proof_block.is_ok());
        chain.try_add_block(identity_proof_block.unwrap());

        assert_eq!(chain.blocks().len(), 8);
        assert!(chain.is_chain_valid());

        let new_chain_from_empty_blocks = CompanyBlockchain::new_from_blocks(vec![]);
        assert!(new_chain_from_empty_blocks.is_err());

        let blocks = chain.blocks();

        for block in blocks {
            assert!(block.validate_plaintext_hash(&company_keys.get_private_key()));
        }

        let new_chain_from_blocks = CompanyBlockchain::new_from_blocks(blocks.to_owned());
        assert!(new_chain_from_blocks.is_ok());
        assert!(new_chain_from_blocks.as_ref().unwrap().is_chain_valid());

        let mut_blocks = chain.blocks_mut();
        mut_blocks[2].hash = Sha256Hash::new("invalidhash");
        let new_chain_from_invalid_blocks =
            CompanyBlockchain::new_from_blocks(mut_blocks.to_owned());
        assert!(new_chain_from_invalid_blocks.is_err());
    }
}
