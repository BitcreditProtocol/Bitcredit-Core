use bcr_common::core::NodeId;

use crate::protocol::{
    ProtocolValidationError, Validate,
    blockchain::{
        Block, Blockchain,
        company::{CompanyOpCode, CompanyValidateActionData},
    },
};

impl Validate for CompanyValidateActionData {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        match self.op {
            CompanyOpCode::Update => {
                self.check_authorized_signatory()?;
            }
            CompanyOpCode::InviteSignatory => {
                self.check_authorized_signatory()?;
                if let Some(ref invitee) = self.invitee {
                    self.can_be_invited(invitee)?;
                } else {
                    unreachable!("Invitee has to be set for InviteSignatory");
                }
            }
            CompanyOpCode::RemoveSignatory => {
                self.check_authorized_signatory()?;
                if let Some(ref removee) = self.removee {
                    self.can_be_removed(removee)?;
                } else {
                    unreachable!("Removee has to be set for RemoveSignatory");
                }
            }
            CompanyOpCode::SignatoryAcceptInvite => {
                self.check_invited()?;
            }
            CompanyOpCode::SignatoryRejectInvite => {
                self.check_invited()?;
            }
            CompanyOpCode::SignCompanyBill => {
                self.check_authorized_signatory()?;
            }
            CompanyOpCode::IdentityProof => {
                self.check_accepted_or_authorized()?;
                if let Some(ref identity_proof_data) = self.identity_proof_data {
                    if let Some(reference_block_id) = identity_proof_data.2 {
                        match self
                            .blockchain
                            .blocks()
                            .iter()
                            .find(|b| b.id() == reference_block_id)
                        {
                            Some(reference_block) => {
                                // reference block has to be either a Create, or Accept block
                                if !matches!(
                                    reference_block.op_code(),
                                    CompanyOpCode::Create | CompanyOpCode::SignatoryAcceptInvite
                                ) {
                                    return Err(ProtocolValidationError::InvalidReferenceBlock);
                                }
                            }
                            // reference block has to exist, if it's set
                            None => {
                                return Err(ProtocolValidationError::InvalidReferenceBlock);
                            }
                        }
                    }

                    // validate identity proof
                    let proof = &identity_proof_data.0;
                    let data = &identity_proof_data.1;

                    if data.node_id != self.signer_node_id {
                        return Err(ProtocolValidationError::InvalidIdentityProof);
                    }

                    if data.company_node_id.as_ref() != Some(&self.company_id) {
                        return Err(ProtocolValidationError::InvalidIdentityProof);
                    }

                    proof
                        .verify(data)
                        .map_err(|_| ProtocolValidationError::InvalidIdentityProof)?;
                } else {
                    unreachable!("Identity Proof has to have identity proof data");
                }
            }
            _ => return Err(ProtocolValidationError::InvalidCompanyAction),
        }

        Ok(())
    }
}

impl CompanyValidateActionData {
    fn check_authorized_signatory(&self) -> Result<(), ProtocolValidationError> {
        if !self
            .blockchain
            .is_authorized_signatory(&self.signer_node_id, &self.company_keys)
            .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?
        {
            return Err(ProtocolValidationError::CallerMustBeSignatory);
        }
        Ok(())
    }

    fn check_accepted_or_authorized(&self) -> Result<(), ProtocolValidationError> {
        let authorized_signer = self
            .blockchain
            .is_authorized_signatory(&self.signer_node_id, &self.company_keys)
            .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?;
        let accepted_but_not_identified_signer = self
            .blockchain
            .is_accepted_but_not_identified_signatory(&self.signer_node_id, &self.company_keys)
            .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?;

        if authorized_signer || accepted_but_not_identified_signer {
            Ok(())
        } else {
            Err(ProtocolValidationError::CallerMustBeSignatory)
        }
    }

    fn check_invited(&self) -> Result<(), ProtocolValidationError> {
        if !self
            .blockchain
            .is_invited(&self.signer_node_id, &self.company_keys)
            .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?
        {
            return Err(ProtocolValidationError::NotInvitedAsSignatory);
        }
        Ok(())
    }

    fn can_be_invited(&self, invitee: &NodeId) -> Result<(), ProtocolValidationError> {
        if !self
            .blockchain
            .can_be_invited(invitee, &self.company_keys)
            .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?
        {
            return Err(ProtocolValidationError::SignatoryAlreadySignatory(
                invitee.to_string(),
            ));
        }
        Ok(())
    }

    fn can_be_removed(&self, removee: &NodeId) -> Result<(), ProtocolValidationError> {
        if !self
            .blockchain
            .can_be_removed(removee, &self.company_keys)
            .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?
        {
            return Err(ProtocolValidationError::NotASignatory(removee.to_string()));
        }

        // check if it's the last authorized signatory
        let authorized_signer = self
            .blockchain
            .is_authorized_signatory(removee, &self.company_keys)
            .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?;
        let num_authorized_signers = self
            .blockchain
            .num_authorized_signers(&self.company_keys)
            .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?;

        if authorized_signer && num_authorized_signers == 1 {
            return Err(ProtocolValidationError::CantRemoveLastSignatory);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{
        BlockId, City, Country, Date, Email, Identification, Name, Timestamp,
        blockchain::company::{
            CompanyBlock, CompanyBlockchain,
            block::{
                CompanyCreateBlockData, CompanyIdentityProofBlockData,
                CompanyInviteSignatoryBlockData, CompanyRemoveSignatoryBlockData,
                CompanySignatoryAcceptInviteBlockData, CompanySignatoryRejectInviteBlockData,
                SignatoryType,
            },
        },
        crypto::BcrKeys,
        tests::tests::{
            node_id_test, node_id_test_another, private_key_test, private_key_test_another,
            signed_identity_proof_test, test_ts, valid_address,
        },
    };

    use super::*;

    fn valid_company_validate_action_data(chain: CompanyBlockchain) -> CompanyValidateActionData {
        CompanyValidateActionData {
            blockchain: chain,
            company_id: node_id_test(),
            signer_node_id: node_id_test(),
            op: CompanyOpCode::Update,
            company_keys: BcrKeys::from_private_key(&private_key_test()),
            invitee: None,
            removee: None,
            identity_proof_data: None,
        }
    }

    fn valid_company_chain() -> CompanyBlockchain {
        let mut chain = CompanyBlockchain::new(
            &CompanyCreateBlockData {
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
            &BcrKeys::from_private_key(&private_key_test()),
            &BcrKeys::from_private_key(&private_key_test()),
            Timestamp::now() - 10,
        )
        .unwrap();
        let test_signed_identity = signed_identity_proof_test();
        let identity_proof_block = CompanyBlock::create_block_for_identity_proof(
            node_id_test(),
            chain.get_latest_block(),
            &CompanyIdentityProofBlockData {
                proof: test_signed_identity.0,
                data: test_signed_identity.1,
                reference_block: Some(chain.get_latest_block().id()),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            &BcrKeys::from_private_key(&private_key_test()),
            Timestamp::now() - 9,
        )
        .unwrap();
        assert!(chain.try_add_block(identity_proof_block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_invite_signatory_block(mut chain: CompanyBlockchain) -> CompanyBlockchain {
        let block = CompanyBlock::create_block_for_invite_signatory(
            node_id_test(),
            chain.get_latest_block(),
            &CompanyInviteSignatoryBlockData {
                invitee: node_id_test_another(),
                inviter: node_id_test(),
                t: SignatoryType::Solo,
            },
            &BcrKeys::from_private_key(&private_key_test()),
            &BcrKeys::from_private_key(&private_key_test()),
            &node_id_test().pub_key(),
            Timestamp::now() - 8,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_accept_signatory_block(mut chain: CompanyBlockchain) -> CompanyBlockchain {
        let block = CompanyBlock::create_block_for_accept_signatory_invite(
            node_id_test(),
            chain.get_latest_block(),
            &CompanySignatoryAcceptInviteBlockData {
                accepter: node_id_test_another(),
            },
            &BcrKeys::from_private_key(&private_key_test_another()),
            &BcrKeys::from_private_key(&private_key_test()),
            Timestamp::now() - 7,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_reject_signatory_block(mut chain: CompanyBlockchain) -> CompanyBlockchain {
        let block = CompanyBlock::create_block_for_reject_signatory_invite(
            node_id_test(),
            chain.get_latest_block(),
            &CompanySignatoryRejectInviteBlockData {
                rejecter: node_id_test_another(),
            },
            &BcrKeys::from_private_key(&private_key_test_another()),
            &BcrKeys::from_private_key(&private_key_test()),
            Timestamp::now() - 7,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_identity_proof_block(mut chain: CompanyBlockchain) -> CompanyBlockchain {
        let test_signed_identity = signed_identity_proof_test();
        let block = CompanyBlock::create_block_for_identity_proof(
            node_id_test(),
            chain.get_latest_block(),
            &CompanyIdentityProofBlockData {
                proof: test_signed_identity.0,
                data: test_signed_identity.1,
                reference_block: Some(chain.get_latest_block().id()),
            },
            &BcrKeys::from_private_key(&private_key_test_another()),
            &BcrKeys::from_private_key(&private_key_test()),
            Timestamp::now() - 6,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_remove_signatory_block(mut chain: CompanyBlockchain) -> CompanyBlockchain {
        let block = CompanyBlock::create_block_for_remove_signatory(
            node_id_test(),
            chain.get_latest_block(),
            &CompanyRemoveSignatoryBlockData {
                removee: node_id_test_another(),
                remover: node_id_test(),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            &BcrKeys::from_private_key(&private_key_test()),
            Timestamp::now() - 5,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    #[test]
    fn test_validate_create() {
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::Create;
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::InvalidCompanyAction));
    }

    #[test]
    fn test_validate_update() {
        let data = valid_company_validate_action_data(valid_company_chain());
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_update_not_signatory() {
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::CallerMustBeSignatory));
    }

    #[test]
    fn test_validate_invite_signatory() {
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::InviteSignatory;
        data.invitee = Some(node_id_test_another());
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_invite_signatory_not_signatory() {
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::InviteSignatory;
        data.invitee = Some(node_id_test_another());
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::CallerMustBeSignatory));
    }

    #[test]
    fn test_validate_invite_signatory_already_signatory_creator() {
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::InviteSignatory;
        data.invitee = Some(node_id_test());
        let result = data.validate();
        assert_eq!(
            result,
            Err(ProtocolValidationError::SignatoryAlreadySignatory(
                node_id_test().to_string()
            ))
        );
    }

    #[test]
    fn test_validate_invite_signatory_already_signatory_invited() {
        let mut data =
            valid_company_validate_action_data(add_invite_signatory_block(valid_company_chain()));
        data.op = CompanyOpCode::InviteSignatory;
        data.invitee = Some(node_id_test_another());
        let result = data.validate();
        assert_eq!(
            result,
            Err(ProtocolValidationError::SignatoryAlreadySignatory(
                node_id_test_another().to_string()
            ))
        );
    }

    #[test]
    fn test_validate_remove_signatory() {
        let mut data =
            valid_company_validate_action_data(add_invite_signatory_block(valid_company_chain()));
        data.op = CompanyOpCode::RemoveSignatory;
        data.removee = Some(node_id_test_another());
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_remove_signatory_accepted() {
        let mut data = valid_company_validate_action_data(add_accept_signatory_block(
            add_invite_signatory_block(valid_company_chain()),
        ));
        data.op = CompanyOpCode::RemoveSignatory;
        data.removee = Some(node_id_test_another());
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_remove_signatory_not_signatory() {
        let mut data =
            valid_company_validate_action_data(add_invite_signatory_block(valid_company_chain()));
        data.op = CompanyOpCode::RemoveSignatory;
        data.removee = Some(node_id_test_another());
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::CallerMustBeSignatory));
    }

    #[test]
    fn test_validate_remove_signatory_not_signatory_reject() {
        let mut data = valid_company_validate_action_data(add_reject_signatory_block(
            add_invite_signatory_block(valid_company_chain()),
        ));
        data.op = CompanyOpCode::RemoveSignatory;
        data.removee = Some(node_id_test_another());
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::CallerMustBeSignatory));
    }

    #[test]
    fn test_validate_remove_signatory_last_signatory() {
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::RemoveSignatory;
        data.removee = Some(node_id_test());
        let result = data.validate();
        assert_eq!(
            result,
            Err(ProtocolValidationError::CantRemoveLastSignatory)
        );
    }

    #[test]
    fn test_validate_remove_signatory_not_last_signatory() {
        let mut data = valid_company_validate_action_data(add_identity_proof_block(
            add_accept_signatory_block(add_invite_signatory_block(valid_company_chain())),
        ));
        data.op = CompanyOpCode::RemoveSignatory;
        data.removee = Some(node_id_test());
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_accept_signatory() {
        let mut data =
            valid_company_validate_action_data(add_invite_signatory_block(valid_company_chain()));
        data.op = CompanyOpCode::SignatoryAcceptInvite;
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_accept_signatory_not_invited() {
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::SignatoryAcceptInvite;
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::NotInvitedAsSignatory));
    }

    #[test]
    fn test_validate_accept_signatory_not_invited_reject() {
        let mut data = valid_company_validate_action_data(add_reject_signatory_block(
            add_invite_signatory_block(valid_company_chain()),
        ));
        data.op = CompanyOpCode::SignatoryAcceptInvite;
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::NotInvitedAsSignatory));
    }

    #[test]
    fn test_validate_accept_signatory_not_invited_remove() {
        let mut data = valid_company_validate_action_data(add_remove_signatory_block(
            add_invite_signatory_block(valid_company_chain()),
        ));
        data.op = CompanyOpCode::SignatoryAcceptInvite;
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::NotInvitedAsSignatory));
    }

    #[test]
    fn test_validate_reject_signatory() {
        let mut data =
            valid_company_validate_action_data(add_invite_signatory_block(valid_company_chain()));
        data.op = CompanyOpCode::SignatoryRejectInvite;
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_reject_signatory_not_invited() {
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::SignatoryRejectInvite;
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::NotInvitedAsSignatory));
    }

    #[test]
    fn test_validate_reject_signatory_not_invited_reject() {
        let mut data = valid_company_validate_action_data(add_reject_signatory_block(
            add_invite_signatory_block(valid_company_chain()),
        ));
        data.op = CompanyOpCode::SignatoryRejectInvite;
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::NotInvitedAsSignatory));
    }

    #[test]
    fn test_validate_reject_signatory_not_invited_remove() {
        let mut data = valid_company_validate_action_data(add_remove_signatory_block(
            add_invite_signatory_block(valid_company_chain()),
        ));
        data.op = CompanyOpCode::SignatoryRejectInvite;
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::NotInvitedAsSignatory));
    }

    #[test]
    fn test_validate_sign_bill() {
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::SignCompanyBill;
        data.signer_node_id = node_id_test();
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_sign_bill_not_signer() {
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::SignCompanyBill;
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::CallerMustBeSignatory));
    }

    #[test]
    fn test_validate_sign_bill_not_signer_added() {
        let mut data = valid_company_validate_action_data(add_identity_proof_block(
            add_accept_signatory_block(add_invite_signatory_block(valid_company_chain())),
        ));
        data.op = CompanyOpCode::SignCompanyBill;
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_sign_bill_not_signer_removed() {
        let mut data = valid_company_validate_action_data(add_remove_signatory_block(
            add_identity_proof_block(add_accept_signatory_block(add_invite_signatory_block(
                valid_company_chain(),
            ))),
        ));
        data.op = CompanyOpCode::SignCompanyBill;
        data.signer_node_id = node_id_test_another();
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::CallerMustBeSignatory));
    }

    #[test]
    fn test_validate_identity_proof() {
        let (proof, mut d) = signed_identity_proof_test();
        d.company_node_id = Some(node_id_test());
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::IdentityProof;
        data.signer_node_id = node_id_test();
        data.identity_proof_data = Some((proof, d, Some(BlockId::first())));
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_identity_proof_no_ref_block() {
        let (proof, mut d) = signed_identity_proof_test();
        d.company_node_id = Some(node_id_test());
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::IdentityProof;
        data.signer_node_id = node_id_test();
        data.identity_proof_data = Some((proof, d, None));
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_identity_proof_wrong_block_id() {
        let (proof, mut d) = signed_identity_proof_test();
        d.company_node_id = Some(node_id_test());
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::IdentityProof;
        data.signer_node_id = node_id_test();
        data.identity_proof_data = Some((proof, d, Some(BlockId::first().add(1))));
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::InvalidReferenceBlock));
    }

    #[test]
    fn test_validate_identity_proof_invalid_proof() {
        let (proof, d) = signed_identity_proof_test();
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::IdentityProof;
        data.signer_node_id = node_id_test();
        data.identity_proof_data = Some((proof, d, Some(BlockId::first())));
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::InvalidIdentityProof));
    }

    #[test]
    fn test_validate_identity_not_signer() {
        let (proof, mut d) = signed_identity_proof_test();
        d.company_node_id = Some(node_id_test());
        let mut data = valid_company_validate_action_data(valid_company_chain());
        data.op = CompanyOpCode::IdentityProof;
        data.signer_node_id = node_id_test_another();
        data.identity_proof_data = Some((proof, d, Some(BlockId::first())));
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::CallerMustBeSignatory));
    }

    #[test]
    fn test_validate_identity_accepted() {
        let (_, mut d) = signed_identity_proof_test();
        d.company_node_id = Some(node_id_test());
        d.node_id = node_id_test_another();
        let proof = d
            .sign(&node_id_test_another(), &private_key_test_another())
            .unwrap();
        let mut data = valid_company_validate_action_data(add_accept_signatory_block(
            add_invite_signatory_block(valid_company_chain()),
        ));
        data.op = CompanyOpCode::IdentityProof;
        data.signer_node_id = node_id_test_another();
        data.identity_proof_data = Some((proof, d, Some(BlockId::first())));
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_identity_not_accepted() {
        let (proof, mut d) = signed_identity_proof_test();
        d.company_node_id = Some(node_id_test());
        let mut data =
            valid_company_validate_action_data(add_invite_signatory_block(valid_company_chain()));
        data.op = CompanyOpCode::IdentityProof;
        data.signer_node_id = node_id_test_another();
        data.identity_proof_data = Some((proof, d, Some(BlockId::first())));
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::CallerMustBeSignatory));
    }
}
