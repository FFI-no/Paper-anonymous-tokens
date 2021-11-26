mod util;

use std::fmt::Display;

use atpmd::atpm_pairing::{
    keys::PublicKey,
    tokens::{PairingSignedToken, PairingTokenEngine},
};
use atpmd::TokenEngine;
use serialport::SerialPort;

use structopt::StructOpt;

#[derive(StructOpt)]
struct Opts {
    #[structopt(short, long, default_value = "127.0.0.1")]
    address: String,

    #[structopt(short, long, default_value = "8000")]
    port: u16,
}

// {{{ Errors

#[derive(Debug)]
enum Errors {
    Io,
    Serial,
    Deserialization,
    Utf8,
}

impl Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl std::error::Error for Errors {}

impl From<serialport::Error> for Errors {
    fn from(_: serialport::Error) -> Self {
        Self::Serial
    }
}

impl From<std::str::Utf8Error> for Errors {
    fn from(_: std::str::Utf8Error) -> Self {
        Self::Utf8
    }
}

impl From<serde_json::Error> for Errors {
    fn from(_: serde_json::Error) -> Self {
        Self::Deserialization
    }
}

impl From<std::io::Error> for Errors {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

// }}}

fn get_data(port: &mut dyn SerialPort) -> Result<PairingSignedToken<Box<[u8]>>, Errors> {
    let mut data: Vec<u8> = vec![];

    loop {
        if port.bytes_to_read()? == 0 {
            continue;
        }

        let mut b = [0];
        port.read(&mut b)?;
        data.push(b[0]);

        if data.len() >= 4 {
            let len = data.len();
            if data[len - 4] == b'\r'
                && data[len - 3] == b'\n'
                && data[len - 2] == b'\r'
                && data[len - 1] == b'\n'
            {
                break;
            }
        }
    }

    Ok(serde_json::from_str(std::str::from_utf8(&data)?)?)
}

fn open_port_and_run(
    client: &mut reqwest::blocking::Client,
    uri: &str,
    key: &PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    // Take the first serial port
    let port = serialport::available_ports()
        .expect("No ports found!")
        .pop()
        .expect("Got no port");

    let mut port = serialport::new(port.port_name, 9600)
        .open()
        .expect("Failed to open port");

    loop {
        let signed_token = get_data(port.as_mut());
        if let Err(e) = &signed_token {
            match e {
                Errors::Io => {
                    return Err(Box::new(Errors::Io));
                }
                Errors::Serial => {
                    return Err(Box::new(Errors::Serial));
                }
                e => println!("{}", e),
            }
        }
        let signed_token = signed_token.unwrap();

        // Verify that the token is valid myself
        if !PairingTokenEngine::verify(&signed_token, &key) {
            println!("This is an invalid token");
            continue;
        }

        // Get the resource, anonlymously
        let resource = client
            .post(format!("{}/resource", uri))
            .json(&signed_token)
            .send()?
            .text()?;

        println!("{}", resource);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Opts::from_args();

    let uri = format!("http://{}:{}", options.address, options.port);

    // Dirty hack with blocking client to not having to deal with async in the closure
    let mut client = reqwest::blocking::Client::new();
    // Get the public key
    let key: PublicKey = client.get(format!("{}/keys/public", uri)).send()?.json()?;

    loop {
        match open_port_and_run(&mut client, &uri, &key) {
            Err(e) => {
                println!("{}", e);
            }
            Ok(()) => (),
        }
    }
}
