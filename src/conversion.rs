use hex::decode;

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;
use sha2::{Digest, Sha256};

pub fn byte_to_bit(mut dec: u32, bit: u8) -> String {
    let mut bin = String::new();
    let mut temp: u32;

    while dec != 0 {
        temp = dec % 2;
        dec = dec / 2;
        bin.push_str(&temp.to_string());
    }

    let fin = "00000000000000000000000000000000";
    let len = bin.len();

    if len != bit as usize {
        let to_add = bit as usize - len;
        bin.push_str(&fin[0..to_add]);
    }

    bin.chars().rev().collect::<String>()
}

pub fn bit_to_bytes_array(bit: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();

    let mut temp = 0;

    while temp < bit.len() {
        let byte = usize::from_str_radix(&bit[temp..temp + 8], 2).unwrap();
        bytes.push(byte as u8);
        temp = temp + 8;
    }

    bytes
}

pub fn byte_array_to_bit(byte_arr: &Vec<u8>) -> String {
    let mut bits = String::new();

    for i in byte_arr {
        let bin = byte_to_bit(*i as u32, 8);
        bits.push_str(&bin);
    }

    bits
}

pub fn sha256sum(byte_array: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(byte_array);

    //Sha256sum of the entropy_byte
    let result = hasher.finalize();

    result.to_vec()
}

pub fn hmac_sha512(input: String) -> String {
    type HmacSha512 = Hmac<Sha512>;

    let mut mac =
        HmacSha512::new_from_slice(&input.as_bytes()).expect("HMAC can take key of any size");

    let result = mac.finalize().into_bytes();

    let mut hash_of_seed = String::new();

    for i in &result {
        let bin = byte_to_bit(*i as u32, 8);
        hash_of_seed.push_str(&bin);
    }

    hash_of_seed
}

pub fn privatekey_to_publickey(private_key: &str) -> String {
    let temp_priv_key_bytes = bit_to_bytes_array(&private_key);

    let secp = Secp256k1::new();

    let p1 = SecretKey::from_slice(&temp_priv_key_bytes[0..32]).expect("Failed");

    let p2 = PublicKey::from_secret_key(&secp, &p1);

    let public_key_bytes = decode(&p2.to_string()).unwrap();

    let public_key_bits = byte_array_to_bit(&public_key_bytes);

    public_key_bits
}

pub fn binary_addition(bin1: &str, bin2: &str) -> String {
    let mut binary_string1 = bin1.to_string();
    let mut binary_string2 = bin2.to_string();

    if binary_string1.len() > binary_string2.len() {
        let diff = binary_string1.len() - binary_string2.len();
        let v = vec!["0"; diff].join("");

        binary_string2 = v + &binary_string2;
    } else {
        let diff = binary_string2.len() - binary_string1.len();
        let v = vec!["0"; diff].join("");

        binary_string1 = v + &binary_string1;
    }

    let string1_array: Vec<char> = binary_string1.chars().collect();
    let string2_array: Vec<char> = binary_string2.chars().collect();
    let mut result = String::new();
    let mut reminder: u8 = 0;

    for (i, j) in string1_array.iter().zip(&string2_array).rev() {

        let int_i = i.to_digit(10).unwrap();
        let int_j = j.to_digit(10).unwrap();

        if int_i + int_j == 0 {
            if reminder == 0 {
                result.push('0');
      
            } else {
                result.push('1');
                reminder=0;
            }
        } else if int_i + int_j == 1 {

            if reminder == 0{
                result.push('1');
              
            }
            else{
                result.push('0');
                reminder=1;
            }


        }
        else if int_i + int_j == 2{

            if reminder == 0{
                println!("JI");
                result.push('0');
                reminder=1;
            }
            else{
                println!("JfaeI");
                result.push('1');
                reminder=1;
            }


        }
    }

    result.chars().rev().collect::<String>()
}
