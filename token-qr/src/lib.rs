mod utils;

use std::{convert::{TryFrom, TryInto}, error::Error};

use qrcode::QrCode;
use wasm_bindgen::prelude::*;

use reqwasm::http::Request;

use atpmd::{TokenEngine, atpm_pairing::{keys::{PrivateKey, PublicKey}, tokens::{PairingSignedToken, PairingTokenEngine, RandomizedUnsignedToken}}};

use serde::{Deserialize, Serialize};
use serde_json;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    fn alert(s: &str);
}

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct QrClient {
    width: usize,
    cells: Vec<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct GetToken<M: AsRef<[u8]>> {
    pub point: RandomizedUnsignedToken<M>,
    pub username: String,
    pub password: String,
}

impl<M: AsRef<[u8]> + Serialize> TryFrom<PairingSignedToken<M>> for QrClient {
    type Error = Box<dyn Error>;
    fn try_from(signed: PairingSignedToken<M>) -> Result<Self, Self::Error> {
        // get the signed token in json format
        let signed_token_json = serde_json::to_string(&signed)?;

        // Encode some data into a QR code.
        let code = QrCode::new(signed_token_json.as_bytes())?;

        // get size of qr code
        let width = code.width();

        // get the colors
        let colors = code.to_colors();

        // sanity check
        assert!(colors.len() == width * width);

        Ok(QrClient {
            width,
            cells: colors.into_iter().map(|c| c.select(true, false)).collect(),
        })
    }
}

#[wasm_bindgen]
impl QrClient {
    /// Talks with the server to get a signed token and returns the qrcode of this token.
    pub async fn new(username: String, password: String, resource: String) -> Result<QrClient, String> {
        let key = Request::get("/keys/public")
            .send()
            .await
            .map_err(|e| format!("{}", e))?
            .json::<PublicKey>()
            .await
            .map_err(|e| format!("{}", e))?;

        // Create a new token
        let unsigned_token = PairingTokenEngine::generate(resource.as_bytes());

        // randomize the token
        let (r, randomized) = PairingTokenEngine::randomize(&unsigned_token);

        // This is a bad way of using password authentication, do not do the same
        let get_token_struct = GetToken {
            point: randomized,
            username,
            password,
        };

        let get_token = serde_json::to_string(&get_token_struct)
            .map_err(|e| format!("{}", e))?;

        // small hack to avoid having to clone randomized.
        let GetToken {
            point: randomized,
            username: _,
            password: _
        } = get_token_struct;

        // Send the token and the cidentials to the server to get the token signed
        let signed = Request::post("/sign")
                .body(get_token)
                .send()
                .await
                .map_err(|e| format!("{}", e))?
                .json()
                .await
                .map_err(|e| format!("{}", e))?;

        PairingTokenEngine::verify_signature_and_unrandomize(unsigned_token, randomized, signed, &key, r)
            .map(|t| t.try_into().ok())
            .flatten()
            .ok_or_else(|| "Bad signature".to_owned())
    }

    /// Creates a keypair and returns the qr-code of a token signed with this keypair
    pub async fn self_signed(resource: String) -> Result<QrClient, String> {
        // this method needs to be async, since if not, the compiler complains about IntoWasmAbi
        // or something idk
        
        // Generate a new keypair
        let private_key = PrivateKey::new();
        let key = PublicKey::from(&private_key);

        // Create a new token
        let unsigned_token = PairingTokenEngine::generate(resource.as_bytes());

        // sign the token
        PairingTokenEngine::sign(unsigned_token, &key, |t_prime| PairingTokenEngine::sign_randomized(t_prime, &private_key))
            .unwrap()
            .try_into()
            .map_err(|e| format!("{}", e))
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        self.cells[x * self.width + y]
    }
}
