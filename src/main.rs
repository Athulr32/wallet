use hex::encode;
use hmac::{Hmac, Mac};

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;
use wallet::conversion::binary_addition;
use std::io;
use wallet::conversion::bit_to_bytes_array;
use wallet::conversion::byte_to_bit;
use wallet::conversion::hmac_sha512;
use wallet::conversion::privatekey_to_publickey;
use wallet::entropy_generator::Entropy;
use wallet::master_key::MasterKeys;
use wallet::mnemonic::get_mnemonics_from_entropy;
use wallet::seed_gen::Seed;
use wallet::verify_mnemonic;

//Only bytes and binary
//Bytes in vector<u8> and binary in string form

//Following BIP39 BIP43 BIP44

fn main() {
    //     println!("Enter the total number of mnemonic words to be generated 1) 12 2)24 Press 1/2");

    //     let mut num_of_word:u8;

    //         loop{
    //             let mut num_of_words = String::new();
    //             io::stdin().read_line(&mut num_of_words).expect("Failed to read");
    //             num_of_word  = match num_of_words.trim().parse(){
    //                 Ok(num)=>num,
    //                 Err(err)=>{
    //                     println!("Hi {err}");
    //                     continue;
    //                 }
    //             };

    //             if num_of_word==1 || num_of_word==2{
    //                 break
    //             }else{
    //                println!("Enter valid number");
    //             }

    //         }

    //     //generate random entropy bytes
    //     let mut random_entropy = Entropy::new(num_of_word);

    //     //sh256sum of the entropy and adding the checksum
    //     random_entropy.sha256sum();
    //     println!("{:?}",random_entropy);

    //    //Get words of each 11 bits
    //     let mnemonics=get_mnemonics_from_entropy(random_entropy);
    //     println!("{:?}",mnemonics);

    let mnemonic_string =
        String::from("turtle front uncle idea crush write shrug there lottery flower risk shell"); //String::from("fluid industry raccoon industry amateur tattoo cinnamon dog favorite will catalog huge");
    let mnemonic_string = mnemonic_string.trim();

    let valid = verify_mnemonic(&mnemonic_string);

    let seed = Seed::gen(&mnemonic_string);

    let (seed_hash, seed_hash_byte) = seed.hash_of_seed();

    let master_keys = MasterKeys::gen(&seed_hash, &seed_hash_byte);

    let key = Keys::derivation(&master_keys);
    
}

//Derivation Path m/44'/60'/0'/0

struct Keys {
    coin: String,
    private_key: String,
    public_key: String,
    chain_code: String,
    index: u32,
}

impl Keys {

    fn derivation(master_keys: &MasterKeys) {


        const PURPOSE: u32 = 0x8000002C + 43;
        const COIN_TYPE: u32 = 60; //ETH
        const ACCOUNT: u32 = 0;
        const CHANGE: u32 = 0;
        let mut temp_priv_key: String = master_keys.private_key.to_string();
        let mut temp_pub_key: String = master_keys.public_key.to_string();
        let mut temp_chain_code: String = master_keys.chain_code.to_string();

        //purpose branch // Hardened Derivation
        let input_to_hash = temp_priv_key + &temp_chain_code + &byte_to_bit(PURPOSE, 32);

        let purpose_branch_hash = hmac_sha512(input_to_hash);

         temp_priv_key = binary_addition(&purpose_branch_hash[0..256], &temp_priv_key);

        temp_pub_key = privatekey_to_publickey(&temp_priv_key);
        temp_chain_code = purpose_branch_hash[256..].to_string();

        //Coin type  // Hardened Derivation

        let input_to_hash = temp_priv_key + &temp_chain_code + &byte_to_bit(COIN_TYPE, 32);

        let coin_type_branch_hash = hmac_sha512(input_to_hash);

        temp_priv_key = coin_type_branch_hash[0..256].to_string();
        temp_pub_key = privatekey_to_publickey(&temp_priv_key);
        temp_chain_code = coin_type_branch_hash[256..].to_string();

        //ACCOUNT //Hardened Derivation

        let input_to_hash = temp_priv_key + &temp_chain_code + &byte_to_bit(ACCOUNT, 32);

        let account_type_branch_hash = hmac_sha512(input_to_hash);

        temp_priv_key = account_type_branch_hash[0..256].to_string();
        temp_pub_key = privatekey_to_publickey(&temp_priv_key);
        temp_chain_code = account_type_branch_hash[256..].to_string();

        
        //Change 

        let input_to_hash = temp_pub_key + &temp_chain_code + &byte_to_bit(CHANGE, 32);

        let account_type_branch_hash = hmac_sha512(input_to_hash);

        temp_priv_key = account_type_branch_hash[0..256].to_string();
        temp_pub_key = privatekey_to_publickey(&temp_priv_key);
        temp_chain_code = account_type_branch_hash[256..].to_string();



    }




}
