mod util;

use atpmd::atpm_pairing::{
    keys::PublicKey,
    tokens::{PairingSignedToken, PairingTokenEngine, RandomizedSignedToken},
};
use atpmd::TokenEngine;
use reqwest::blocking::{Client, Response};
use serde::Serialize;
use subtle::{Choice, CtOption};

use util::GetToken;

use qrcode::QrCode;
use image::Luma;

fn get_token<T: AsRef<[u8]> + Clone + Serialize>(client: &Client, key: &PublicKey, message: T) -> PairingSignedToken<T> {
    // Create a new token
    let unsigned_token = PairingTokenEngine::generate(message);

    // Get access to the resource
    PairingTokenEngine::sign(unsigned_token, &key, |unsigned| {
        // This is a bad way of using password authentication, do not do the same
        let get_token = GetToken {
            point: unsigned.clone(),
            username: "user".to_owned(),
            password: "password123".to_owned(),
        };

        // Send the token and the cidentials to the server to get the token signed
        let signed = client
            .post("http://127.0.0.1:8000/sign")
            .json(&get_token)
            .send()
            .and_then(|res: Response| res.json());

        // Return the signed token
        let is_signed = signed.is_ok();
        CtOption::new(
            signed.unwrap_or_else(|_e| RandomizedSignedToken::default()),
            Choice::from(if is_signed { 1 } else { 0 }),
        )
    })
    .unwrap()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Dirty hack with blocking client to not having to deal with async in the closure
    let client = reqwest::blocking::Client::new();
    // Get the public key
    let key: PublicKey = client
        .get("http://127.0.0.1:8000/keys/public")
        .send()?
        .json()?;

    let signed_token = get_token(&client, &key, b"resource");

    // Verify that the token is valid myself, not strictly needed since the sign function takes
    // care fo this
    let success = PairingTokenEngine::verify(&signed_token, &key);
    if success {
        println!("Got a valid token");
    } else {
        println!("Got an invalid token");
        return Ok(());
    }

    let bytes = serde_json::to_string(&signed_token).unwrap();

    // Encode some data into bits.
    let code = QrCode::new(bytes.as_bytes()).unwrap();

    // Render the bits into an image.
    let image = code.render::<Luma<u8>>().build();

    println!("Saving qr code to '/tmp/qrcode.png'");
    // Save the image.
    image.save("/tmp/qrcode.png").unwrap();

    Ok(())
}
