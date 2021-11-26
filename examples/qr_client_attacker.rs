mod util;

use atpmd::atpm_pairing::{
    keys::{PrivateKey, PublicKey},
    tokens::PairingTokenEngine,
};
use atpmd::TokenEngine;

use image::Luma;
use qrcode::QrCode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the public key
    let private_key = PrivateKey::new();
    let key = PublicKey::from(&private_key);

    let signed_token = PairingTokenEngine::sign(
        PairingTokenEngine::generate(b"resource"),
        &key,
        |randomized_unsigned| {
            PairingTokenEngine::sign_randomized(randomized_unsigned, &private_key)
        },
    )
    .unwrap();

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
