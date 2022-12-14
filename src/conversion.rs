
use sha2::{Sha256,Digest};

pub fn byte_to_bit(mut dec:u32,bit:u8)->String{

    let mut bin = String::new();
    let mut temp:u32;
    
    while dec!=0{
        temp = dec%2;
        dec=dec/2;
        bin.push_str(&temp.to_string());
    }

    let fin = "00000000".to_string();
    let len = bin.len();
    
    if len!=bit as usize {
        let to_add = bit as usize -len;
        bin.push_str(&fin[0..to_add]);
    }

    bin.chars().rev().collect::<String>()
}

pub fn bit_to_bytes_array(bit:&str)->Vec<u8>{

    let mut bytes:Vec<u8> = Vec::new();
 
    let mut temp=0;
    while temp<bit.len(){
 
       let byte = usize::from_str_radix(&bit[temp..temp+8],2).unwrap();
       bytes.push(byte as u8);
       temp=temp+8;
 
    }
 
    bytes
 
 
 }


pub fn sha256sum(byte_array:Vec<u8>)->Vec<u8>{
    let mut hasher = Sha256::new();
    hasher.update(byte_array);

    //Sha256sum of the entropy_byte
    let result = hasher.finalize();

    result.to_vec()

}
