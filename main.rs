mod padding;
mod boolean_ops;
mod sha256;

use tfhe::boolean::prelude::*;
use padding::pad_sha256_input;
use sha256::{sha256_fhe, bools_to_hex};

fn main() {
    let (ck, sk) = gen_keys();

    // CLIENT PADS DATA AND ENCRYPTS IT

    let padded_input = pad_sha256_input("hello world");
    let encrypted_input = encrypt_bools(&padded_input, &ck);

    // SERVER COMPUTES OVER THE ENCRYPTED PADDED DATA

    let encrypted_output = sha256_fhe(encrypted_input, &sk);

    // CLIENT DECRYPTS THE OUTPUT

    let output = decrypt_bools(&encrypted_output, &ck);
    let outhex = bools_to_hex(output);

    println!("{}", outhex);
}

fn encrypt_bools(bools: &Vec<bool>, ck: &ClientKey) -> Vec<Ciphertext> {
    let mut ciphertext = vec![];

    for bool in bools {
        ciphertext.push(ck.encrypt(*bool));
    }
    ciphertext
}

fn decrypt_bools(ciphertext: &Vec<Ciphertext>, ck: &ClientKey) -> Vec<bool> {
    let mut bools = vec![];

    for cipher in ciphertext {
        bools.push(ck.decrypt(&cipher));
    }
    bools
}