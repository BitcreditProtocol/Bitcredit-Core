use bcr_ebill_core::timestamp::Timestamp;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct TimeApi {
    pub timestamp: Timestamp,
}

impl TimeApi {
    pub async fn get_atomic_time() -> Self {
        TimeApi {
            timestamp: Timestamp::now(),
        }
    }
}
