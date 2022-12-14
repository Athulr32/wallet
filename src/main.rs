use wallet::conversion::{byte_to_bit,sha256sum,bit_to_bytes_array};
use wallet::words::WORDS;
use wallet::entropy_generator::{Entropy};
use std::io;
use wallet::mnemonic::get_mnemonics_from_entropy;



fn verify_mnemonic(mnemonic_enter:&str)->bool{


   let user_mnemonic_array:Vec<&str> = mnemonic_enter.split(" ").collect();
   let len = user_mnemonic_array.len();
   let mut index=0;
   println!("{len}");
   if len == 12{
      index=4;
   }
   else if len == 24 {
      index = 8;
   }
   else{
      return false;
   }

   let mut user_mnemonic_bit_array=Vec::new();

   for i in &user_mnemonic_array{
      let index = WORDS.iter().position(|&x| x==*i).unwrap();
      user_mnemonic_bit_array.push(byte_to_bit(index as u32,11));
   }

   //Entropy+Checksum
   let user_entropy = user_mnemonic_bit_array.join(""); 

   //Checksum
   let user_checksum_bit = &user_entropy[user_entropy.len()-index..];

   //Entropy
   let user_entropy_without_checksum = &user_entropy[0..user_entropy.len()-index];

   //Converting the entropy bit to byte for sha256 hashing
   let user_entropy_byte_array = bit_to_bytes_array(user_entropy_without_checksum);

   let sha256_of_user_entropy_byte_array = sha256sum(user_entropy_byte_array);


   //Check if the checksum matches

   let user_checksum_bit_from_hash = byte_to_bit(sha256_of_user_entropy_byte_array[0] as  u32,8);

   //Check whether chekcksum match if yes seedphrase is valid else no
   let mnemonic_valid = &user_checksum_bit_from_hash[0..index]==user_checksum_bit;

   mnemonic_valid


}



fn main(){

    println!("Enter the total number of mnemonic words to be generated 1) 12 2)24 Press 1/2");

    let mut num_of_word:u8;
    
        loop{
            let mut num_of_words = String::new();
            io::stdin().read_line(&mut num_of_words).expect("Failed to read");
            num_of_word  = match num_of_words.trim().parse(){
                Ok(num)=>num,
                Err(err)=>{
                    println!("Hi {err}");
                    continue;
                }
            };

            println!("{}",num_of_word);
            
            if num_of_word==1 || num_of_word==2{
                break
            }
      
        }
         
    
    //generate random entropy bytes
    let mut random_entropy = Entropy::new(num_of_word);

    //sh256sum of the entropy and adding the checksum
    random_entropy.sha256sum();
    println!("{:?}",random_entropy);

    let mnemonics=get_mnemonics_from_entropy(random_entropy);
    println!("{:?}",mnemonics);

    let mnemonic_enter = mnemonics.join(" "); //String::from("fluid industry raccoon industry amateur tattoo cinnamon dog favorite will catalog huge");
   
    let valid =  verify_mnemonic(&mnemonic_enter);
    println!("{}",valid);    

  
}


