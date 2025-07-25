pub mod bitcoin;
pub mod file_storage;
pub mod mint;
pub mod time;

use thiserror::Error;

/// Generic error type
#[derive(Debug, Error)]
pub enum Error {
    /// all errors originating from external API requests
    #[error("External Request error: {0}")]
    ExternalApi(#[from] reqwest::Error),

    /// all errors originating from the external bitcoin API
    #[error("External Bitcoin API error: {0}")]
    ExternalBitcoinApi(#[from] bitcoin::Error),

    /// all errors originating from the external mint API
    #[error("External Mint API error: {0}")]
    ExternalMintApi(#[from] mint::Error),

    /// all errors originating from the external file storage API
    #[error("External File Storage API error: {0}")]
    ExternalFileStorageApi(#[from] file_storage::Error),
}
