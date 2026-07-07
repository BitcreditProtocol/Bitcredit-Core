use crate::protocol::{
    ProtocolValidationError, Validate,
    blockchain::identity::{IdentityOpCode, IdentityValidateActionData},
};

impl Validate for IdentityValidateActionData {
    fn validate(&self) -> std::result::Result<(), crate::protocol::ProtocolValidationError> {
        match self.op {
            // anon users can update identity and sign personal bills
            IdentityOpCode::Update | IdentityOpCode::SignPersonBill => {
                self.check_signer()?;
            }
            // only identified users can do these
            IdentityOpCode::SignCompanyBill
            | IdentityOpCode::CreateCompany
            | IdentityOpCode::InviteSignatory
            | IdentityOpCode::AcceptSignatoryInvite
            | IdentityOpCode::RejectSignatoryInvite
            | IdentityOpCode::RemoveSignatory => {
                self.check_identified_signer()?;
            }
            IdentityOpCode::IdentityProof => {
                self.check_signer()?;
                if let Some(ref identity_proof_data) = self.identity_proof_data {
                    let proof = &identity_proof_data.0;
                    let data = &identity_proof_data.1;

                    if data.node_id != self.id {
                        return Err(ProtocolValidationError::InvalidIdentityProof);
                    }

                    proof
                        .verify(data)
                        .map_err(|_| ProtocolValidationError::InvalidIdentityProof)?;
                } else {
                    unreachable!("Identity Proof has to have identity proof data");
                }
            }
            _ => return Err(ProtocolValidationError::InvalidIdentityAction),
        }
        Ok(())
    }
}

impl IdentityValidateActionData {
    fn check_signer(&self) -> Result<(), ProtocolValidationError> {
        if !self
            .blockchain
            .is_creator(&self.id, &self.keys)
            .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?
        {
            return Err(ProtocolValidationError::CallerMustBeCreator);
        }
        Ok(())
    }

    fn check_identified_signer(&self) -> Result<(), ProtocolValidationError> {
        if !self
            .blockchain
            .is_identified(&self.id, &self.keys)
            .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?
        {
            return Err(ProtocolValidationError::CallerMustBeIdentifiedCreator);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{
        ProtocolValidationError, Validate,
        blockchain::{
            Blockchain,
            identity::{
                IdentityBlock, IdentityBlockchain, IdentityOpCode, IdentityProofBlockData,
                IdentityValidateActionData,
            },
        },
        crypto::BcrKeys,
        tests::tests::{
            empty_identity, node_id_test, node_id_test_another, private_key_test,
            signed_identity_proof_test, test_ts,
        },
    };

    fn valid_identity_chain() -> IdentityBlockchain {
        IdentityBlockchain::new(
            &empty_identity(),
            &BcrKeys::from_private_key(&private_key_test()),
            test_ts() - 7,
        )
        .unwrap()
    }

    fn add_identity_proof_block(mut chain: IdentityBlockchain) -> IdentityBlockchain {
        let (proof, data) = signed_identity_proof_test();
        let block = IdentityBlock::create_block_for_identity_proof(
            chain.get_latest_block(),
            &IdentityProofBlockData { proof, data },
            &BcrKeys::from_private_key(&private_key_test()),
            test_ts() - 6,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn valid_identity_validate_action_data(
        chain: IdentityBlockchain,
    ) -> IdentityValidateActionData {
        IdentityValidateActionData {
            blockchain: chain,
            id: node_id_test(),
            op: IdentityOpCode::Update,
            keys: BcrKeys::from_private_key(&private_key_test()),
            identity_proof_data: None,
        }
    }

    #[test]
    fn test_validate_update() {
        let mut data =
            valid_identity_validate_action_data(add_identity_proof_block(valid_identity_chain()));
        data.op = IdentityOpCode::Update;
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_update_for_anon() {
        let mut data = valid_identity_validate_action_data(valid_identity_chain());
        data.op = IdentityOpCode::Update;
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_sign_person_bill() {
        let mut data =
            valid_identity_validate_action_data(add_identity_proof_block(valid_identity_chain()));
        data.op = IdentityOpCode::SignPersonBill;
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_sign_person_bill_anon() {
        let mut data = valid_identity_validate_action_data(valid_identity_chain());
        data.op = IdentityOpCode::SignPersonBill;
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_sign_company_bill() {
        let mut data =
            valid_identity_validate_action_data(add_identity_proof_block(valid_identity_chain()));
        data.op = IdentityOpCode::SignCompanyBill;
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_sign_company_bill_anon() {
        let mut data = valid_identity_validate_action_data(valid_identity_chain());
        data.op = IdentityOpCode::SignCompanyBill;
        let result = data.validate();
        assert!(matches!(result, Err(_)));
    }

    #[test]
    fn test_validate_create_company() {
        let mut data =
            valid_identity_validate_action_data(add_identity_proof_block(valid_identity_chain()));
        data.op = IdentityOpCode::CreateCompany;
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_create_company_anon() {
        let mut data = valid_identity_validate_action_data(valid_identity_chain());
        data.op = IdentityOpCode::CreateCompany;
        let result = data.validate();
        assert!(matches!(result, Err(_)));
    }

    #[test]
    fn test_validate_invite_signatory() {
        let mut data =
            valid_identity_validate_action_data(add_identity_proof_block(valid_identity_chain()));
        data.op = IdentityOpCode::InviteSignatory;
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_remove_signatory() {
        let mut data =
            valid_identity_validate_action_data(add_identity_proof_block(valid_identity_chain()));
        data.op = IdentityOpCode::RemoveSignatory;
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_accept_signatory_invite() {
        let mut data =
            valid_identity_validate_action_data(add_identity_proof_block(valid_identity_chain()));
        data.op = IdentityOpCode::AcceptSignatoryInvite;
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_reject_signatory_invite() {
        let mut data =
            valid_identity_validate_action_data(add_identity_proof_block(valid_identity_chain()));
        data.op = IdentityOpCode::RejectSignatoryInvite;
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_identity_proof() {
        let (proof, d) = signed_identity_proof_test();
        let mut data = valid_identity_validate_action_data(valid_identity_chain());
        data.op = IdentityOpCode::IdentityProof;
        data.identity_proof_data = Some((proof, d));
        let result = data.validate();
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_identity_proof_invalid_proof() {
        let (proof, mut d) = signed_identity_proof_test();
        d.node_id = node_id_test_another();
        let mut data = valid_identity_validate_action_data(valid_identity_chain());
        data.op = IdentityOpCode::IdentityProof;
        data.identity_proof_data = Some((proof, d));
        let result = data.validate();
        assert_eq!(result, Err(ProtocolValidationError::InvalidIdentityProof));
    }
}
