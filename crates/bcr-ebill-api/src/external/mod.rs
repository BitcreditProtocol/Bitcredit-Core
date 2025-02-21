pub mod bitcoin;
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
}
