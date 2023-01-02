use hex::encode;
// use hmac::{Hmac, Mac};
use hmac_sha512::HMAC;
use secp256k1::PublicKey;
use secp256k1::Secp256k1;
use secp256k1::SecretKey;
use sha2::Sha512;
use wallet::conversion::base58check;
use wallet::keys::ExtendedPubKey;
use wallet::keys::Index;

use wallet::keys::ExtendedPrivKey;
use wallet::seed_gen::Seed;
use wallet::verify_mnemonic;

use bitcoin::network::constants::Network;
use bitcoin::util::base58::{from, from_check};
use bitcoin::util::bip32::ChildNumber;
use bitcoin_hashes::hmac::HmacEngine;
use bitcoin_hashes::{sha512, Hash, HashEngine, Hmac};
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
    //     let mnemonics=get_mnemonics_from_entropy(random_entropy).unwrap();
    //     println!("{:?}",mnemonics);

    let mnemonic_string = String::from(
        "observe impact right enforce shrug tribe fatal tray feel penalty orbit obtain",
    ); //String::from("fluid industry raccoon industry amateur tattoo cinnamon dog favorite will catalog huge");
    let mnemonic_string = mnemonic_string.trim();

    let valid = verify_mnemonic(&mnemonic_string);

    let seed = Seed::gen(&mnemonic_string);

    let master_key = ExtendedPrivKey::new_master(&seed);

    let account = master_key.ckd_priv(Index::Hardened { index: 44 });
    let account1 = account.ckd_priv(Index::Hardened { index: 60 });
    let account2 = account1.ckd_priv(Index::Hardened { index: 0 });
    let account3 = account2.ckd_priv(Index::Normal { index: 0 });

    let address = account3.ckd_priv(Index::Normal { index: 0 });

    println!("{}",base58check(&address.private_key[..].to_vec()));



}

//Derivation Path m/44'/60'/0'/0
