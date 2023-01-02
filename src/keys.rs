
use crate::{
    conversion::{byte_array_to_bit, byte_to_bit},
    seed_gen::Seed,
};
use hex::encode;
use hmac::{Hmac, Mac};
use num::BigUint;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;
use tiny_keccak::{Keccak,Hasher};


pub enum Network{
    Ethereum,
    Bitcoin
}

#[derive(Debug)]

pub struct ChainCode(pub Vec<u8>);

#[derive(Debug)]
pub enum Index {
    //0 - 2^31
    Normal { index: u32 },

    Hardened { index: u32 },
}

#[derive(Debug)]
pub struct ExtendedPrivKey {
    pub private_key: SecretKey,
    pub chain_code: ChainCode,
    pub index: Index,
    pub depth: u8,
}

#[derive(Debug)]
pub struct ExtendedPubKey {
    pub public_key: PublicKey,
    pub chain_code: ChainCode,
    pub index: Index,
    pub depth: u8,
}

impl ExtendedPubKey {
    pub fn from_privkey(privkey: ExtendedPrivKey) -> Self {
        let secp = Secp256k1::new();
        Self {
            public_key: PublicKey::from_secret_key(&secp, &privkey.private_key),
            chain_code: privkey.chain_code,
            index: privkey.index,
            depth: privkey.depth,
        }
    }

    pub fn ckd_pub(&self, indexs: Index) -> Result<ExtendedPubKey, String> {
        if let Index::Normal { index } = indexs {
            type HmacSha512 = Hmac<Sha512>;

            let mut mac = HmacSha512::new_from_slice(&self.chain_code.0)
                .expect("HMAC can take key of any size");

            mac.update(&self.public_key.serialize());
            mac.update(&index.to_be_bytes());

            let result = mac.finalize().into_bytes();

            let sk = SecretKey::from_slice(&result[0..32]).unwrap();
            let secp = Secp256k1::new();

            let pub_tweaked = self.public_key.add_exp_tweak(&secp, &sk.into()).unwrap();

            Ok(ExtendedPubKey {
                public_key: pub_tweaked,
                chain_code: ChainCode(result[32..].to_vec()),
                depth: self.depth + 1,
                index: indexs,
            })
        } else {
            Err("Index should be less than 2^31".to_string())
        }
    }
}

impl ExtendedPrivKey {
    pub fn new_master(seed: &Seed) -> Self {
        type HmacSha512 = Hmac<Sha512>;

        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC can take key of any size");

        mac.update(&seed.seed_byte);

        let result = mac.finalize().into_bytes();

        Self {
            private_key: SecretKey::from_slice(&result[0..32]).unwrap(),
            chain_code: ChainCode(result[32..].to_vec()),
            index: Index::Normal { index: 0 },
            depth: 0,
        }
    }

    pub fn ckd_priv(&self, index: Index) -> ExtendedPrivKey {
        type HmacSha512 = Hmac<Sha512>;

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code.0).expect("HMAC can take key of any size");

        match index {
            Index::Hardened { mut index } => {
                mac.update(&[0u8]);
                mac.update(&self.private_key[..]);
                index = 0x80000000 + index;
                mac.update(&index.to_be_bytes())
            }
            Index::Normal { index } => {
                let mut secp = Secp256k1::new();
                mac.update(&PublicKey::from_secret_key(&secp, &self.private_key).serialize());

                mac.update(&index.to_be_bytes())
            }
        }

        let result = mac.finalize().into_bytes();

        let sk = SecretKey::from_slice(&result[0..32]).unwrap();
        let sk_tweak = sk.add_tweak(&self.private_key.into()).unwrap();

        ExtendedPrivKey {
            private_key: sk_tweak,
            chain_code: ChainCode(result[32..].to_vec()),
            index: index,
            depth: &self.depth + 1,
        }
    }

    //Ethereum address
    pub fn generate_address(&self,network:Network) {

        if let Network::Ethereum = network{
            //Kecck
            let mut output =[0;32];
            let secp = Secp256k1::new();
            let pub_key = PublicKey::from_secret_key(&secp,&self.private_key).serialize_uncompressed();
            println!("{}",encode(pub_key));

            let  mut shaa3 = Keccak::v256();
            shaa3.update(&pub_key[1..]);
            shaa3.finalize(&mut output);
            println!("{}",encode(&output[12..]));
        
            
        }



    }
}
