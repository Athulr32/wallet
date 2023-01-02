use crate::conversion::byte_to_bit;
use bitcoin::util::bip32::ExtendedPrivKey;
use hex::encode;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha2::Sha512;

#[derive(Debug)]
pub struct Seed {
    pub seed_byte: [u8; 64],
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


}
