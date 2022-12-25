
use hmac::{Hmac, Mac};
use sha2::Sha512;
use pbkdf2::{pbkdf2};
use crate::conversion::byte_to_bit;
use hex::encode;


#[derive(Debug)]
pub struct Seed {
     seed_byte: [u8; 64],
     seed_string: String,
    pub seed_hex: String,
}

impl Seed {
    pub fn gen(mnemonic: &str) -> Self {
        let mut seed_byte = [0u8; 64];
        let mut seed_bit = String::new();

        let _ = pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), b"mnemonic", 2048, &mut seed_byte);

        for i in seed_byte {
            let bit = byte_to_bit(i as u32, 8);
            seed_bit.push_str(&bit);
        }

        Self {
            seed_hex: encode(&seed_byte),
            seed_byte: seed_byte,
            seed_string: seed_bit,
        }
    }


    pub fn hash_of_seed(&self) -> (String, Vec<u8>) {
        type HmacSha512 = Hmac<Sha512>;
    
        let mut mac = HmacSha512::new_from_slice(&self.seed_byte).expect("HMAC can take key of any size");
    
        let result = mac.finalize().into_bytes();
    
        let mut hash_of_seed = String::new();
    
        for i in &result {
            let bin = byte_to_bit(*i as u32, 8);
            hash_of_seed.push_str(&bin);
        }
    
        (hash_of_seed, result.to_vec())
    }
    
}

