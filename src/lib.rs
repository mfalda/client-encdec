#![allow(non_snake_case)]

use wasm_bindgen::prelude::*;

mod utils;


use std::iter::repeat;

use aes_gcm_siv::aead::{Aead, generic_array::GenericArray};
use aes_gcm_siv::{Aes256GcmSiv, Nonce, KeyInit};
use argon2::{self, Config, ThreadMode, Variant, Version};
use rand::{rngs::OsRng, RngCore};

extern crate lazy_static;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern {
    fn alert(s: &str);
}

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn greeting(msg: &str) {
    alert(msg);
}

#[wasm_bindgen]
pub fn doubleF(n: i32) -> i32 {
    n * 2
}

#[wasm_bindgen]
pub fn generateSalt() -> String
{
    let mut salt = [0u8; 12];
    OsRng.fill_bytes(&mut salt);

    hex::encode(&salt)
}

#[wasm_bindgen]
pub fn hashPassword(pwd: String, salt: String) -> String
{
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: 10,
        lanes: 4,
        thread_mode: ThreadMode::Sequential,
        secret: &[],
        ad: &[],
        hash_length: 24
    };
    
    let argon2Salt: String = salt.repeat(3);
    let pwd_bytes = pwd.as_bytes();
    let asalt_bytes = argon2Salt.as_bytes();
    let key0: String = argon2::hash_encoded(pwd_bytes, asalt_bytes, &config).unwrap_or_else(|_| String::from(""));
    let mut pieces = key0.split('$');
    let len = pieces.clone().count();

    pieces.nth(len - 1).unwrap_or("").to_string()
}

#[wasm_bindgen]
pub fn encryptText(key: String, salt: String, text: String, pref_len: usize) -> String
{
    let FIXED_SALT: Vec<u8> = repeat(1u8).take(12).collect();

    let key1 = key.clone();

    let (text1, text2): (String, String) =
        if text.len() > pref_len {
            (String::from(&text[..pref_len]), String::from(&text[pref_len..]))
        }
        else {
            (text, String::from(""))
        };

    let sivKey = GenericArray::from_slice(key.as_bytes());
    let siv = Aes256GcmSiv::new(sivKey);
    let nonce = Nonce::from_slice(&FIXED_SALT);
    let res: Vec<u8> = siv.encrypt(nonce, text1.as_ref()).expect("encryption failure!");

    let sivKey1 = GenericArray::from_slice(key1.as_bytes());
    let gcm = Aes256GcmSiv::new(sivKey1);
    let variablePart: Vec<u8> =  gcm.encrypt(Nonce::from_slice(&hex::decode(&salt.as_bytes()).unwrap_or_default()), text2.as_ref()).expect("encryption failure!");

    format!("{}|{}|{}", hex::encode(&res), &salt, hex::encode(&variablePart))
}

#[wasm_bindgen]
pub fn decryptText(key: String, text: String, pref_len: usize) -> String
{
    let FIXED_SALT: Vec<u8> = repeat(1u8).take(12).collect();

	let pos = text.find('|').unwrap_or(0);
    let mut text2: &str = "";

    let mut pos1 = 0;
    if pos > 0 {
        pos1 = utf8_slice::from(&text, pos + 1).find('|').map(|i| i + pos + 1).unwrap_or(0);
        text2 = utf8_slice::from(&text, pos1 + 1);
    }

    let text1 = utf8_slice::till(&text, pos);
    let salt = utf8_slice::slice(&text, pos + 1, pos1);

    let key1 = key.clone();

    let sivKey = GenericArray::from_slice(key.as_bytes());
    let siv = Aes256GcmSiv::new(sivKey);

    let sivKey1 = GenericArray::from_slice(key1.as_bytes());
    let gcm = Aes256GcmSiv::new(sivKey1);

    let decoded_plain1: Result<Vec<u8>, aes_gcm_siv::Error> =  siv.decrypt(Nonce::from_slice(&FIXED_SALT),
                                                hex::decode(text1).unwrap_or_default().as_ref()
                                        );

    let decoded_plain2: Result<Vec<u8>, aes_gcm_siv::Error> = gcm.decrypt(Nonce::from_slice(&hex::decode(&salt).unwrap_or_default()),
                                                hex::decode(text2).unwrap_or_default().as_ref()
                                        );

    if let (Ok(plain1), Ok(plain2)) = (decoded_plain1, decoded_plain2) {
        let mut tmp = String::from(utf8_slice::till(&String::from_utf8(plain1).unwrap_or_default(), pref_len));
        tmp.push_str(std::str::from_utf8(&plain2).unwrap());
        tmp
    }
    else {
        String::from("*****")
    }
}

#[cfg(test)]

mod test {
    use crate::{generateSalt, hashPassword, encryptText, decryptText};

    struct SaltKey {
        salt: String,
        key: String
    }

    lazy_static::lazy_static! {
        static ref SALT_KEY: SaltKey = {
            let salt1 = generateSalt();
            SaltKey {
                salt: salt1.to_owned(),
                key: hashPassword(String::from("O&3p5#2"), salt1)
            }
        };
    }

    #[test]
    fn test_encDec() {       
        let str = "Falda";
        let ciphertext = encryptText(SALT_KEY.key.to_owned(), SALT_KEY.salt.to_owned(), String::from(str), 3);
        print!("0. Encrypted: {}", ciphertext);
        let plaintext = decryptText(SALT_KEY.key.to_owned(), ciphertext, 3);
        print!(" -> {}\n\n", plaintext);
        assert_eq!(plaintext, str);
    }

    #[test]
    fn test_encDec_singleChar() {
        let str = "T";
        let ciphertext = encryptText(SALT_KEY.key.to_owned(), SALT_KEY.salt.to_owned(), String::from(str), 3);
        print!("0. Encrypted: {}", ciphertext);
        let plaintext = decryptText(SALT_KEY.key.to_owned(), ciphertext, 3);
        print!(" -> {}\n\n", plaintext);
        assert_eq!(plaintext, "T");
    }
    #[test]
    fn test_encDec_empty() {
        let str = "";
        let ciphertext = encryptText(SALT_KEY.key.to_owned(), SALT_KEY.salt.to_owned(), String::from(str), 3);
        print!("0. Encrypted: {}", ciphertext);
        let plaintext = decryptText(SALT_KEY.key.to_owned(), ciphertext, 3);
        print!(" -> {}\n\n", plaintext);
        assert_eq!(plaintext, str);
    }

    #[test]
    fn test_encDec_zero() {
        let str = "";
        let ciphertext = encryptText(SALT_KEY.key.to_owned(), SALT_KEY.salt.to_owned(), String::from(str), 0);
        print!("0. Encrypted: {}", ciphertext);
        let plaintext = decryptText(SALT_KEY.key.to_owned(), ciphertext, 0);
        print!(" -> {}\n\n", plaintext);
        assert_eq!(plaintext, str);
    }

    #[test]
    fn test_encDec_short() {
        let str = "Ts";
        let ciphertext = encryptText(SALT_KEY.key.to_owned(), SALT_KEY.salt.to_owned(), String::from(str), 3);
        print!("0. Encrypted: {}", ciphertext);
        let plaintext = decryptText(SALT_KEY.key.to_owned(), ciphertext, 3);
        print!(" -> {}\n\n", plaintext);
        assert_eq!(plaintext, str);
    }

    #[test]
    fn test_decryptText_newlines() {
        let str = "A\nB\rC\tD";
        let ciphertext = encryptText(SALT_KEY.key.to_owned(), SALT_KEY.salt.to_owned(), String::from(str), 3);
        print!("0. Encrypted: {}", ciphertext);
        let plaintext = decryptText(SALT_KEY.key.to_owned(), ciphertext, 3);
        print!(" -> {}\n\n", plaintext);
        assert_eq!(plaintext, str);
    }
}
