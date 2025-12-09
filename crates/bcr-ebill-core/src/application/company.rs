use crate::protocol::{
    City, Country, Date, Email, EmailIdentityProofData, File, Identification, Name, PostalAddress,
    SignedIdentityProof, Timestamp,
    blockchain::company::{CompanyBlockPayload, CompanyCreateBlockData, SignatoryType},
};
use bcr_common::core::NodeId;

use log::warn;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Company {
    pub id: NodeId,
    pub name: Name,
    pub country_of_registration: Option<Country>,
    pub city_of_registration: Option<City>,
    pub postal_address: PostalAddress,
    pub email: Email,
    pub registration_number: Option<Identification>,
    pub registration_date: Option<Date>,
    pub proof_of_registration_file: Option<File>,
    pub logo_file: Option<File>,
    pub creation_time: Timestamp,
    pub signatories: Vec<CompanySignatory>,
    pub status: CompanyStatus,
}

impl Company {
    // checks if the given node id is an authorized signer for this company
    pub fn is_authorized_signer(&self, node_id: &NodeId) -> bool {
        self.signatories.iter().any(|s| {
            &s.node_id == node_id
                && matches!(
                    s.status,
                    CompanySignatoryStatus::InviteAcceptedIdentityProven { .. }
                )
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Copy)]
pub enum CompanyStatus {
    Invited,
    Active,
    None,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompanySignatory {
    pub t: SignatoryType,
    pub node_id: NodeId,
    pub status: CompanySignatoryStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum CompanySignatoryStatus {
    Invited {
        ts: Timestamp,
        inviter: NodeId,
    },
    InviteAccepted {
        ts: Timestamp,
    },
    InviteRejected {
        ts: Timestamp,
    },
    InviteAcceptedIdentityProven {
        ts: Timestamp,
        data: EmailIdentityProofData,
        proof: SignedIdentityProof,
    },
    Removed {
        ts: Timestamp,
        remover: NodeId,
    },
}

impl Company {
    /// Creates a new company from a block data payload
    pub fn from_block_data(data: CompanyCreateBlockData, our_node_id: &NodeId) -> Self {
        // if we're the creator, the company is active, otherwise we have no status in the company at this point
        let status = if our_node_id == &data.creator {
            CompanyStatus::Active
        } else {
            CompanyStatus::None
        };

        Self {
            id: data.id,
            name: data.name,
            country_of_registration: data.country_of_registration,
            city_of_registration: data.city_of_registration,
            postal_address: data.postal_address,
            email: data.email,
            registration_number: data.registration_number,
            registration_date: data.registration_date,
            proof_of_registration_file: data.proof_of_registration_file,
            logo_file: data.logo_file,
            creation_time: data.creation_time,
            signatories: vec![CompanySignatory {
                t: SignatoryType::Solo,
                node_id: data.creator,
                status: CompanySignatoryStatus::InviteAccepted {
                    ts: data.creation_time,
                },
            }],
            status,
        }
    }
    /// Applies data from a block to this company.
    pub fn apply_block_data(
        &mut self,
        data: &CompanyBlockPayload,
        our_node_id: &NodeId,
        timestamp: Timestamp,
    ) {
        match data {
            CompanyBlockPayload::Update(payload) => {
                self.name = payload.name.to_owned().unwrap_or(self.name.to_owned());
                self.email = payload.email.to_owned().unwrap_or(self.email.to_owned());
                self.postal_address.city = payload
                    .postal_address
                    .city
                    .to_owned()
                    .unwrap_or(self.postal_address.city.to_owned());
                self.postal_address.country = payload
                    .postal_address
                    .country
                    .to_owned()
                    .unwrap_or(self.postal_address.country.to_owned());
                self.postal_address.zip = payload
                    .postal_address
                    .zip
                    .to_owned()
                    .or(self.postal_address.zip.to_owned());
                self.postal_address.address = payload
                    .postal_address
                    .address
                    .to_owned()
                    .unwrap_or(self.postal_address.address.to_owned());
                self.country_of_registration = payload
                    .country_of_registration
                    .to_owned()
                    .or(self.country_of_registration.to_owned());
                self.city_of_registration = payload
                    .city_of_registration
                    .to_owned()
                    .or(self.city_of_registration.to_owned());
                self.registration_number = payload
                    .registration_number
                    .to_owned()
                    .or(self.registration_number.to_owned());
                self.registration_date = payload
                    .registration_date
                    .to_owned()
                    .or(self.registration_date.to_owned());
                self.logo_file = payload.logo_file.to_owned().or(self.logo_file.to_owned());
                self.proof_of_registration_file = payload
                    .proof_of_registration_file
                    .to_owned()
                    .or(self.proof_of_registration_file.to_owned());
            }
            CompanyBlockPayload::InviteSignatory(payload) => {
                // if we're invited, set our status to invited, if we're not already invited or accepted
                if CompanyStatus::None == self.status && our_node_id == &payload.invitee {
                    self.status = CompanyStatus::Invited;
                }

                // update signatory data
                if let Some(signatory) = self
                    .signatories
                    .iter_mut()
                    .find(|s| s.node_id == payload.invitee)
                {
                    match signatory.status {
                        CompanySignatoryStatus::InviteRejected { .. }
                        | CompanySignatoryStatus::Removed { .. } => {
                            // invite again
                            signatory.status = CompanySignatoryStatus::Invited {
                                ts: timestamp,
                                inviter: payload.inviter.clone(),
                            }
                        }
                        _ => {
                            // already invited / accepted - ignore,
                            warn!(
                                "Trying to invite {}, although they're already invited/accepted",
                                payload.invitee
                            );
                        }
                    }
                } else {
                    // if the signatory wasn't in the list before - add as invited
                    self.signatories.push(CompanySignatory {
                        t: SignatoryType::Solo,
                        node_id: payload.invitee.to_owned(),
                        status: CompanySignatoryStatus::Invited {
                            ts: timestamp,
                            inviter: payload.inviter.clone(),
                        },
                    });
                }
            }
            CompanyBlockPayload::SignatoryAcceptInvite(payload) => {
                // if we're invited, set our status to active
                if CompanyStatus::Invited == self.status && our_node_id == &payload.accepter {
                    self.status = CompanyStatus::Active;
                }

                // update signatory data
                if let Some(signatory) = self
                    .signatories
                    .iter_mut()
                    .find(|s| s.node_id == payload.accepter)
                {
                    signatory.status = CompanySignatoryStatus::InviteAccepted { ts: timestamp };
                }
            }
            CompanyBlockPayload::SignatoryRejectInvite(payload) => {
                // if we're invited, set our status to None
                if CompanyStatus::Invited == self.status && our_node_id == &payload.rejecter {
                    self.status = CompanyStatus::None;
                }

                // update signatory data
                if let Some(signatory) = self
                    .signatories
                    .iter_mut()
                    .find(|s| s.node_id == payload.rejecter)
                {
                    signatory.status = CompanySignatoryStatus::InviteRejected { ts: timestamp };
                }
            }
            CompanyBlockPayload::RemoveSignatory(payload) => {
                // if we're removed, set our status to none
                if our_node_id == &payload.removee {
                    self.status = CompanyStatus::None;
                }

                // update signatory data
                if let Some(signatory) = self
                    .signatories
                    .iter_mut()
                    .find(|s| s.node_id == payload.removee)
                {
                    signatory.status = CompanySignatoryStatus::Removed {
                        ts: timestamp,
                        remover: payload.remover.clone(),
                    };
                }
            }
            CompanyBlockPayload::IdentityProof(payload) => {
                if let Some(signatory) = self
                    .signatories
                    .iter_mut()
                    .find(|s| s.node_id == payload.data.node_id)
                {
                    // Part of adding a signatory via Accept, or Create
                    if payload.reference_block.is_some() {
                        match signatory.status {
                            CompanySignatoryStatus::InviteAccepted { .. }
                            | CompanySignatoryStatus::InviteAcceptedIdentityProven { .. } => {
                                signatory.status =
                                    CompanySignatoryStatus::InviteAcceptedIdentityProven {
                                        ts: timestamp,
                                        data: payload.data.clone(),
                                        proof: payload.proof.clone(),
                                    }
                            }
                            _ => (), // invalid / irrelevant cases
                        }
                    } else {
                        // only update data
                        if let CompanySignatoryStatus::InviteAcceptedIdentityProven { ts, .. } =
                            signatory.status
                        {
                            signatory.status =
                                CompanySignatoryStatus::InviteAcceptedIdentityProven {
                                    ts,
                                    data: payload.data.clone(),
                                    proof: payload.proof.clone(),
                                }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalSignatoryOverride {
    pub company_id: NodeId,
    pub node_id: NodeId,
    pub status: LocalSignatoryOverrideStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalSignatoryOverrideStatus {
    Hidden, // hide a company signatory locally
}
