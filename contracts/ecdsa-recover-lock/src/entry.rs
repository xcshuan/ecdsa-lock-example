// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::vec::Vec;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::Unpack,
    debug,
    high_level::{load_script, load_tx_hash, load_witness_args},
};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, Secp256k1,
};
use sha2::{Digest, Sha256};

use crate::error::Error;

pub fn main() -> Result<(), Error> {
    // remove below examples and write your code here
    let script = load_script()?;
    let pk_hash: Vec<u8> = script.args().unpack();
    debug!("pk_hash is {:?}", pk_hash);

    let tx_hash = load_tx_hash()?;
    debug!("tx hash is {:?}", tx_hash);

    let witness = load_witness_args(0, Source::Input).unwrap();

    let signature = match witness.lock().to_opt() {
        Some(signature_with_recid) => {
            let signature_with_recid = signature_with_recid.raw_data();
            debug!("signature_with_recid len: {}", signature_with_recid.len());
            if let Ok(recid) = RecoveryId::from_i32(signature_with_recid[0] as i32) {
                match RecoverableSignature::from_compact(&signature_with_recid[1..], recid) {
                    Ok(recoverable_signature) => recoverable_signature,
                    Err(_) => return Err(Error::VerificationError),
                }
            } else {
                return Err(Error::VerificationError);
            }
        }
        None => return Err(Error::VerificationError),
    };

    let secp = Secp256k1::new();
    let public_key = match secp.recover_ecdsa(&Message::from_digest(tx_hash), &signature) {
        Ok(public_key) => public_key,
        Err(_) => return Err(Error::VerificationError),
    };

    let recovered_pk_hash = Sha256::digest(public_key.serialize())[0..20].to_vec();
    if pk_hash != recovered_pk_hash {
        return Err(Error::VerificationError);
    }

    Ok(())
}
