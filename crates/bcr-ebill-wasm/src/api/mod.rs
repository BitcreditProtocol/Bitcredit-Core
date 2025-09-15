use super::Result;
use wasm_bindgen::prelude::*;

pub mod bill;
pub mod company;
pub mod contact;
pub mod general;
pub mod identity;
pub mod identity_proof;
pub mod notification;

#[wasm_bindgen]
pub struct Api;

#[wasm_bindgen]
impl Api {
    #[wasm_bindgen]
    pub fn general() -> general::General {
        general::General::new()
    }

    #[wasm_bindgen]
    pub fn contact() -> contact::Contact {
        contact::Contact::new()
    }

    #[wasm_bindgen]
    pub fn identity() -> identity::Identity {
        identity::Identity::new()
    }

    #[wasm_bindgen]
    pub fn identity_proof() -> identity_proof::IdentityProof {
        identity_proof::IdentityProof::new()
    }

    #[wasm_bindgen]
    pub fn notification() -> notification::Notification {
        notification::Notification::new()
    }

    #[wasm_bindgen]
    pub fn company() -> company::Company {
        company::Company::new()
    }

    #[wasm_bindgen]
    pub fn bill() -> bill::Bill {
        bill::Bill::new()
    }
}
