pub mod conversion;
pub mod master_key;
pub mod mnemonic;
pub mod seed_gen;
pub mod words;
use crate::conversion::{bit_to_bytes_array, byte_to_bit, sha256sum,binary_addition};
use crate::words::WORDS;

#[cfg(test)]
mod tests {
    use crate::conversion::{byte_to_bit, binary_addition};

    #[test]
    fn conversion_test() {
        assert_eq!("01110110", binary_addition("10101010", "11001100"))
    }
}

pub mod entropy_generator {

    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use sha2::{Digest, Sha256};

    #[derive(Debug)]
    pub struct Entropy {
        entropy_byte: Vec<u8>,
        pub entropy_bit: String,
        pub entropy_bit_num: u16,
        checksum_bit_num: u8,
        mnemonic_length: u8,
    }

    impl Entropy {
        pub fn new(num_of_word: u8) -> Self {
            let mut bytes = 0;
            let mut checksum_bit_num = 0;
            let mut mnemonic_length = 0;

            if num_of_word == 1 {
                bytes = 32;
                checksum_bit_num = 8;
                mnemonic_length = 24;
            } else if num_of_word == 2 {
                bytes = 16;
                checksum_bit_num = 4;
                mnemonic_length = 12;
            }

            let mut num = StdRng::from_entropy();
            let mut random_entropy_byte = vec![0u8; bytes];

            //Randong entropy in bytes
            num.try_fill_bytes(&mut random_entropy_byte)
                .expect("Failed to generate words");

            //Converting the byte into bit
            let mut random_entropy_string = String::new();

            // //Convert the byte into bits
            for i in &random_entropy_byte {
                let binary = super::byte_to_bit(*i as u32, 8);
                random_entropy_string.push_str(&binary);
            }

            Self {
                entropy_byte: random_entropy_byte,
                entropy_bit_num: random_entropy_string.len() as u16 + checksum_bit_num as u16,
                entropy_bit: random_entropy_string,
                checksum_bit_num,
                mnemonic_length,
            }
        }

        pub fn sha256sum(&mut self) {
            let mut hasher = Sha256::new();
            hasher.update(&self.entropy_byte);

            //Sha256sum of the entropy_byte
            let result = hasher.finalize();

            //Adding the first checksum_bit_num bits of sha256hash to the entropy_bit
            let byte = result[0];
            let bits = super::byte_to_bit(byte as u32, 8);

            let _ = &self
                .entropy_bit
                .push_str(&bits[0..self.checksum_bit_num as usize]);
        }
    }
}

pub fn verify_mnemonic(mnemonic_enter: &str) -> bool {
    let user_mnemonic_array: Vec<&str> = mnemonic_enter.split(" ").collect();
    let len = user_mnemonic_array.len();
    let index;

    if len == 12 {
        index = 4;
    } else if len == 24 {
        index = 8;
    } else {
        return false;
    }

    let mut user_mnemonic_bit_array = Vec::new();

    for i in &user_mnemonic_array {
        let index = WORDS.iter().position(|&x| x == *i).unwrap();
        user_mnemonic_bit_array.push(byte_to_bit(index as u32, 11));
    }

    //Entropy+Checksum
    let user_entropy = user_mnemonic_bit_array.join("");

    //Checksum
    let user_checksum_bit = &user_entropy[user_entropy.len() - index..];

    //Entropy
    let user_entropy_without_checksum = &user_entropy[0..user_entropy.len() - index];

    //Converting the entropy bit to byte for sha256 hashing
    let user_entropy_byte_array = bit_to_bytes_array(user_entropy_without_checksum);

    let sha256_of_user_entropy_byte_array = sha256sum(user_entropy_byte_array);

    //Check if the checksum matches

    let user_checksum_bit_from_hash = byte_to_bit(sha256_of_user_entropy_byte_array[0] as u32, 8);

    //Check whether chekcksum match if yes seedphrase is valid else no
    let mnemonic_valid = &user_checksum_bit_from_hash[0..index] == user_checksum_bit;

    mnemonic_valid
}
