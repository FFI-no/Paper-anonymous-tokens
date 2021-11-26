use atpmd::atpm_pairing::tokens::RandomizedUnsignedToken;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GetToken<M: AsRef<[u8]>> {
    pub point: RandomizedUnsignedToken<M>,
    pub username: String,
    pub password: String,
}
