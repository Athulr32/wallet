use hex::decode;
use num::BigUint;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::conversion::{byte_array_to_bit, byte_to_bit};
#[derive(Debug)]
pub struct MasterKeys {
    pub private_key: String,
    pub public_key: String,
    pub chain_code: String,
    pub index: u32,
}

impl MasterKeys {
    pub fn gen(seed_hash: &str, seed_hash_byte: &[u8]) -> Self {
        let secp = Secp256k1::new();

        let master_private_key = SecretKey::from_slice(&seed_hash_byte[0..32]).expect("Failed");

        let master_public_key = PublicKey::from_secret_key(&secp, &master_private_key);

        let public_key_bytes = decode(&master_public_key.to_string()).unwrap();

        let master_public_key_bits = byte_array_to_bit(&public_key_bytes);

        let mut master_chain_code = [0u8; 32];

        master_chain_code.copy_from_slice(&seed_hash_byte[32..64]);

        const INDEX: u32 = 0x8000002C;

        Self {
            private_key: seed_hash[0..256].to_string(),
            public_key: master_public_key_bits,
            chain_code: seed_hash[256..].to_string(),
            index:INDEX,
        }
    }
}
