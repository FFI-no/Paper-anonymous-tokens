# Anonymous Tokens with Public Metadata

This project implements two of [Silde and Strand's protocols for anonymous tokens](https://eprint.iacr.org/2021/203.pdf) along with samples. The work was carried out by two undergraduate students during a summer internship at [FFI](https://www.ffi.no/en).

The project requires rustc 1.53.0 or newer.

This code uses experemental libraries, should not be used in production.

## Table of Contents

<!-- vim-markdown-toc GFM -->

* [Documentation](#documentation)
* [Examples](#examples)
	* [Installation dependencies](#installation-dependencies)
		* [Debian/Ubuntu](#debianubuntu)
	* [Server](#server)
		* [Endpoints](#endpoints)
		* [Access of users](#access-of-users)
		* [Configuration](#configuration)
	* [Client](#client)
	* [QR Client and attacker](#qr-client-and-attacker)
	* [QR-code WebApp](#qr-code-webapp)
		* [Installation](#installation)
		* [Description](#description)
	* [QR serial](#qr-serial)
 * [License](#license)
<!-- vim-markdown-toc -->

## Documentation

Generate and open the documentation with

```sh
cargo doc --open --no-deps
```

## Examples

### Installation dependencies

You need [Rust](https://www.rust-lang.org/tools/install) with rustc 1.53.0 or newer installed.

#### Debian/Ubuntu

These programs are needed to compile the examples.
`libudev-dev` are used by the example that communicates with a serial port.

```sh
sudo apt install libudev-dev pkg-config libssl-dev
```

### Server

The project includes a simple server using the Rocket web framework to generate  tokens as QR codes.
This server may act as both the signer and verifier, and is using the pairing based implementation.

This server will serve the webapp, but the webapp needs to be installed.
See the installation section for the webapp.

#### Endpoints

The endpoints of the server:
  - `/keys` A GET request to `/keys/public` will return the public key in JSON format.

  - `/sign` A POST request to this endpoint will sign the point it is sent.  The request has to contain a username, password and a token.  If the user exists and is authorized for the specific resource requested, the token is signed and the signed token is sent back in JSON format. Otherwise an error is returned.

  - `/resource` This endpoint accepts a GET request.  This request has to contain a signed token for the resource.  If the token is previously unused and signed with the correct key the resource is returned.  Otherwise an error is returned.

  - `/static` This endpoint has some static files for the website, including the QR-code webapp.

  - `/` Will redirect to `/static/index.html`.

#### Access of users 

The table below shows what users are on the server, their usernames and passwords, and what resources they have access to.

Username | Password | Resources
-------- | -------- | ---------
user | password123 | resource
user1 | password123 | resource, resource1
user2 | password123 | resource, resource1, resource2
user3 | password123 | resource, resource1, resource2, resource3

#### Configuration

The server may be configured using the `Rocket.toml` file, see [Rocket](https://rocket.rs/) for more information.

### Client

The client connects to the server and gets the public key.
It will try to get a token signed and use this token to access the resource twice.
The first time it should succeed, and the second time fail (since the token is already used at that point).

### QR Client and attacker

The QR-client connects to the server and gets the public key.
It tries to get a token signed, and creates a QR-code based on this signed token.
This QR-code is saved as the file `/tmp/qrcode.png`.

The QR-attacker creates its own key-pair, creates a token and signs it.
A QR-code is crated with this signed token and it is saved as the file `/tmp/qrcode.png`.

### QR-code WebApp

#### Installation

To compile and install the webapp, you need [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) and [npm](https://nodejs.org/en/).
First the webapp needs to be compiled.
```sh
cd token-qr
wasm-pack build --target=web
cd -
```
Installing the webapp
```sh
cd static
npm install
cd -
```

#### Description

The webapp consists of two parts, a core written in rust and compiled to webassembly, and a JavaScript wrapper around this core.

The wrapper prompts the user for a username, password and the ability to get a self-signed token.
This is sent to the core.
The generated QR-code is rendered to the screen.

If the core is asked to return a self-signed token, it will create a key-pair and a token and sign the token with this key-pair.
A QR-code is generated and returned.

Otherwise, the core gets the key from the server, generates a token and tries to get the server to sign this token.
A QR-code is created based on this signed token and returned.

### QR serial

Needs `libudev-dev` and `pkg-config` to be installed.

This application expects data to be passed from a serial port.
This data should be the same information as in the QR-codes from the examples, and terminated with `\r\n\r\n`.
It will print if the tokens are valid or invalid, and communicates with the server example.

## License

This repository is available under the MIT License. See the license file for details.
