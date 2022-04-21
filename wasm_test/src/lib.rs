use wasm_bindgen::prelude::*; 
use hex_literal::hex;
use sha2::{Sha256, Digest};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce}; // Or `Aes128GcmSiv`
use aes_gcm_siv::aead::{Aead, NewAead};
use rand::{distributions::Alphanumeric, Rng};
use openssl::rsa::{Rsa, Padding};
use openssl::aes::{AesKey, aes_ige};
use openssl::symm::Mode;
use openssl::rand::rand_bytes;
use pbkdf2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2
};
use rand_core::OsRng;


#[wasm_bindgen]
pub fn add2numbers(n1:i32,n2:i32)->i32{
    n1+n2
}

#[wasm_bindgen]
pub fn square(n1:i32)->i32{
    n1*n1
}

#[wasm_bindgen]
pub fn chiffre(mut password:String)->String{
      // create a Sha256 object
      const SALT:&str="a31158c6-9cb0-11ec-b909-0242ac120002";

      let mut hasher = Sha256::new();
      
      password.push_str(SALT);
      // write input message
      hasher.update(password);
  
      // read hash digest and consume hasher
      let result = hasher.finalize();
      
      return format!("{:x}", result);
}

#[wasm_bindgen]
pub struct CryptedMessage{
    cipherText: Vec<u8>,
    key: String,
    nonce:Nonce, 
}

#[wasm_bindgen]
pub fn pbkdf2_derivation(password : String) -> String{
    let password_to_hash = password.as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    Pbkdf2.hash_password_simple(password_to_hash, salt.as_ref()).unwrap().to_string()
}
#[wasm_bindgen]
pub fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_string(),
        Some((idx, _)) => (&s[..idx]).to_string(),
    }
}
#[wasm_bindgen]
pub fn generateRandomString(size:u8)->String{
    let s: String = rand::thread_rng()
    .sample_iter(&Alphanumeric)
    .take(12)
    .map(char::from)
    .collect();
    return s;
}

#[wasm_bindgen]
pub fn crypt_aes_gcm_siv(message:String,password:String)->CryptedMessage{
    let secret_key=String::from(pbkdf2_derivation(password));
    let  split=secret_key.split("$");
    let vec: Vec<&str> = split.collect();
    //println!("{}",secret_key);
    let reduced_key=truncate(vec[4], 32);
    let key = Key::from_slice(reduced_key.as_bytes());

    let mut buf = [0; 32];
    rand_bytes(&mut buf).unwrap();
    let aeskey = AesKey::new_encrypt(&buf).unwrap();
    //let cle = format!("{:?}",key);
    //println!("{}",cle);
    
    //let cipher = Aes256GcmSiv::new(key);
    let cipher = Aes256GcmSiv::new(aeskey);

    let randString=format!("{}",generateRandomString(12));
    let nonce = Nonce::from_slice(randString.as_bytes()); // 96-bits; unique per message

    let ciphertext = cipher.encrypt(nonce, message.as_ref())
        .expect("encryption failure!");  // NOTE: handle this error to avoid panics!
        println!("encrypted text:{}",format!("{:?}",ciphertext));

    
    let crypted_message = CryptedMessage{
        cipherText: ciphertext,
        key:reduced_key.to_string(),
        nonce: *nonce,
    } ;
    
    return crypted_message;
}
#[wasm_bindgen]
pub fn decrypt_aes_gcm_siv(crypted_message:CryptedMessage)->String{
    let key = Key::from_slice(crypted_message.key.as_bytes());
    let cipher = Aes256GcmSiv::new(key);
    let nonce=crypted_message.nonce;
    let plaintext = cipher.decrypt(&nonce, crypted_message.cipherText.as_ref())
        .expect("decryption failure!");  // NOTE: handle this error to avoid panics!

    let message = String::from_utf8_lossy(&plaintext);
    println!("Clear text:{}",message);
    return message.to_string();
}