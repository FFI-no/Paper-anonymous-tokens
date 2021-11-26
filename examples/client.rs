mod util;

use atpmd::atpm_pairing::{
    keys::PublicKey,
    tokens::{PairingTokenEngine, RandomizedSignedToken},
};
use atpmd::TokenEngine;
use reqwest::blocking::Response;
use subtle::{Choice, CtOption};

use util::GetToken;

fn main() -> Result<(), reqwest::Error> {
    // Dirty hack with blocking client to not having to deal with async in the closure
    let client = reqwest::blocking::Client::new();
    // Get the public key
    let key: PublicKey = client
        .get("http://127.0.0.1:8000/keys/public")
        .send()?
        .json()?;

    // The resource we want access to
    let message = b"resource";

    // Create a new token
    let unsigned_token = PairingTokenEngine::generate(message);

    // Get access to the resource
    let signed_token = PairingTokenEngine::sign(unsigned_token, &key, |unsigned| {
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
    .unwrap();

    // Get the resource, anonlymously
    let resource = client
        .post("http://127.0.0.1:8000/resource")
        .json(&signed_token)
        .send()?
        .text()?;

    println!("{}", resource);

    // Try again, but the token should be invalid now
    let resource = client
        .post("http://127.0.0.1:8000/resource")
        .json(&signed_token)
        .send()?
        .text()?;

    println!("{}", resource);

    Ok(())
}
