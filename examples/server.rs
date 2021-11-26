#[macro_use]
extern crate rocket;

mod util;

use atpmd::atpm_pairing::tokens::{PairingSignedToken, RandomizedSignedToken};
use atpmd::{
    atpm_pairing::{
        keys::{PrivateKey, PublicKey},
        tokens::PairingTokenEngine,
    },
    RandomizedUnsignedToken, TokenEngine,
};

use rocket::http::Status;
use rocket::fs::NamedFile;
use rocket::response::Redirect;
use rocket::serde::json::Json;
use rocket::State;
use sha2::{Digest, Sha512};
use std::path::{Path, PathBuf};
use std::{collections::HashMap, sync::Mutex};

use util::GetToken;

struct Keys {
    private: PrivateKey,
    public: PublicKey,
}

#[get("/public")]
/// This will return the public key of the server
fn public_key(keys: &State<Keys>) -> Json<&PublicKey> {
    Json::from(&keys.public)
}

#[post("/", data = "<point>")]
/// If it is a valid user, and the user has access to the resource, their token will be signed.
fn sign(
    keys: &State<Keys>,
    access_control: &State<AccessControl>,
    users: &State<Users>,
    point: Json<GetToken<Box<[u8]>>>,
) -> Json<Option<RandomizedSignedToken<Box<[u8]>>>> {
    let get_token = point.into_inner();
    if !users.verify(&get_token.username, get_token.password) {
        return Json::from(None);
    }

    let metadata = get_token.point.metadata();

    let resource = std::str::from_utf8(&metadata);

    if resource.is_err() {
        return Json::from(None);
    }

    if !access_control.check_access(get_token.username, resource.unwrap()) {
        return Json::from(None);
    }

    let signed = PairingTokenEngine::sign_randomized(&get_token.point, &keys.private);

    Json::from(if bool::from(signed.is_some()) {
        Some(signed.unwrap())
    } else {
        None
    })
}

#[post("/", data = "<point>")]
/// If it is a valid, unused token, the resource will be returned.
fn resource(
    keys: &State<Keys>,
    used: &State<UsedTokens>,
    point: Json<PairingSignedToken<Box<[u8]>>>,
) -> Result<&'static str, Status> {
    let point = point.into_inner();

    if !used.contains(&point) && PairingTokenEngine::verify(&point, &keys.public) {
        used.push(point);
        Ok("you have access to this resource")
    } else {
        Err(Status::Unauthorized)
    }
}

/// List of used tokens
struct UsedTokens {
    tokens: Mutex<Vec<PairingSignedToken<Box<[u8]>>>>,
}

impl UsedTokens {
    fn new() -> Self {
        Self {
            tokens: Mutex::new(Vec::new()),
        }
    }

    fn contains(&self, token: &PairingSignedToken<Box<[u8]>>) -> bool {
        self.tokens
            .lock()
            .map(|list| if list.contains(token) { Some(()) } else { None })
            .ok()
            .flatten()
            .is_some()
    }

    fn push(&self, token: PairingSignedToken<Box<[u8]>>) {
        self.tokens.lock().map(|mut list| list.push(token)).unwrap()
    }
}

struct Users {
    // usernames and hash of passwords
    users: HashMap<String, [u8; 64]>,
}

impl Users {
    fn new() -> Self {
        Users {
            users: HashMap::new(),
        }
    }

    fn insert(&mut self, user: impl Into<String>, password: impl AsRef<[u8]>) {
        let mut hasher = Sha512::new();
        hasher.update(password);
        let hash = hasher.finalize();

        let mut password = [0u8; 64];
        for (h, p) in hash.iter().zip(password.iter_mut()) {
            *p = *h;
        }

        self.users.insert(user.into(), password);
    }

    fn verify(&self, user: impl Into<String>, password: impl AsRef<[u8]>) -> bool {
        if let Some(correct) = self.users.get(&user.into()) {
            let mut hasher = Sha512::new();
            hasher.update(password);
            let hash = hasher.finalize();

            let mut password = [0u8; 64];
            for (h, p) in hash.iter().zip(password.iter_mut()) {
                *p = *h;
            }

            &password == correct
        } else {
            false
        }
    }
}

struct AccessControl {
    // map of list of usernames
    resources: HashMap<String, HashMap<String, ()>>,
}

impl AccessControl {
    fn new() -> Self {
        AccessControl {
            resources: HashMap::new(),
        }
    }

    fn assign(&mut self, user: impl Into<String>, resource: impl Into<String>) {
        let resource = resource.into();
        let user = user.into();

        if let Some(resource) = self.resources.get_mut(&resource) {
            resource.insert(user, ());
        } else {
            let mut map = HashMap::new();
            map.insert(user, ());
            self.resources.insert(resource.into(), map);
        }
    }

    fn check_access(&self, user: impl Into<String>, resource: impl Into<String>) -> bool {
        let resource = resource.into();
        let user = user.into();

        self.resources
            .get(&resource)
            .and_then(|map| map.get(&user))
            .is_some()
    }
}

// Follow the structure of Express
// It is whether you ignore the serve shows it couldn't find / or /user
// or you edit manually index.html and other paths for images etc.
#[get("/<file..>")]
pub async fn file(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/").join(file)).await.ok()
}

#[get("/")]
fn home() -> Redirect {
    Redirect::to("/static/index.html")
}

#[launch]
fn rocket() -> _ {
    // Generate keypair
    let private = PrivateKey::new();
    let public = PublicKey::from(&private);

    // create a new user
    let mut users = Users::new();
    users.insert("user", "password123");
    users.insert("user1", "password123");
    users.insert("user2", "password123");
    users.insert("user3", "password123");

    // Let the user have access to this thing
    let mut ac = AccessControl::new();
    ac.assign("user", "resource");
    ac.assign("user1", "resource");
    ac.assign("user2", "resource");
    ac.assign("user3", "resource");

    ac.assign("user1", "resource1");
    ac.assign("user2", "resource1");
    ac.assign("user3", "resource1");

    ac.assign("user2", "resource2");
    ac.assign("user3", "resource2");

    ac.assign("user3", "resource3");

    // launch server
    rocket::build()
        .manage(Keys { private, public })
        .manage(users)
        .manage(ac)
        .manage(UsedTokens::new())
        .mount("/keys", routes![public_key])
        .mount("/sign", routes![sign])
        .mount("/resource", routes![resource])
        .mount("/static", routes![file])
        .mount("/", routes![home])
}
