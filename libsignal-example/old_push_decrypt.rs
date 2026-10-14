//! Decrypt pending 2016-era Signal envelopes (type 1, SignalMessage) using the session records saved in an
//! old app dump. Line protocol on stdin (all binary as hex):
//!   ID <identity public 33B> <identity private 32B>
//!   SESSION <name> <device> <SessionRecord bytes>
//!   MSG <idx> <name> <device> <SignalMessage bytes>
//! Output on stdout: `OK <idx> <plaintext hex>` or `ERR <idx> <reason>`; sessions advance as messages are
//! decrypted, in input order.

use std::io::BufRead;

use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::TryRngCore;

fn main() {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut store: Option<InMemSignalProtocolStore> = None;
    let local = ProtocolAddress::new("self".to_owned(), DeviceId::try_from(1u8).expect("valid"));
    for line in std::io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.first().copied() {
            Some("ID") => {
                let public = IdentityKey::decode(&hex::decode(f[1]).expect("hex")).expect("identity public");
                let private = PrivateKey::deserialize(&hex::decode(f[2]).expect("hex")).expect("identity private");
                store = Some(InMemSignalProtocolStore::new(IdentityKeyPair::new(public, private), 1).expect("store"));
            }
            Some("SESSION") => {
                let s = store.as_mut().expect("ID first");
                let dev: u8 = f[2].parse().expect("device");
                let addr = ProtocolAddress::new(f[1].to_owned(), DeviceId::try_from(dev).expect("device"));
                match SessionRecord::deserialize(&hex::decode(f[3]).expect("hex")) {
                    Ok(rec) => {
                        s.store_session(&addr, &rec).now_or_never().expect("sync").expect("store session");
                        // trust the identity recorded in the session (it was trusted when the session was made)
                        if let Ok(Some(their)) = rec.remote_identity_key_bytes().map(|o| o.and_then(|b| IdentityKey::decode(&b).ok())) {
                            let _ = s.save_identity(&addr, &their).now_or_never();
                        }
                    }
                    Err(e) => eprintln!("session {} {}: {}", f[1], dev, e),
                }
            }
            Some("MSG") => {
                let s = store.as_mut().expect("ID first");
                let idx = f[1];
                let dev: u8 = f[3].parse().expect("device");
                let addr = ProtocolAddress::new(f[2].to_owned(), DeviceId::try_from(dev).expect("device"));
                let bytes = hex::decode(f[4]).expect("hex");
                let res = SignalMessage::try_from(bytes.as_slice()).and_then(|m| {
                    message_decrypt_signal(&m, &addr, &local, &mut s.session_store, &mut s.identity_store, &mut rng)
                        .now_or_never()
                        .expect("sync")
                });
                match res {
                    Ok(pt) => println!("OK {} {}", idx, hex::encode(pt)),
                    Err(e) => println!("ERR {} {}", idx, e.to_string().replace(char::is_whitespace, "_")),
                }
            }
            _ => {}
        }
    }
}
