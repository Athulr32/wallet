use crate::entropy_generator::Entropy;
use crate::words::WORDS;

pub fn get_mnemonics_from_entropy(random_entropy: Entropy) -> Vec<&'static str> {
    let split_num: usize = random_entropy.entropy_bit_num as usize / 11 as usize;
    println!("{}", split_num);

    //get the mnemonic words from the words list
    let mut mnemonic_words = Vec::with_capacity(split_num);

    let len_of_entropy = random_entropy.entropy_bit_num as usize;

    let mut track: usize = 0;

    while track < len_of_entropy {
        let data = &random_entropy.entropy_bit[track..track + 11];
        let decimal_data = usize::from_str_radix(data, 2).expect("Failed to convert");
        mnemonic_words.push(WORDS[decimal_data]);
        track = track + 11;
    }

    mnemonic_words
}
