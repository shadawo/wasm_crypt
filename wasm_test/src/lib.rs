//use std::str::from_utf8;
//use std::str::pattern::StrSearcher;

//use aes::cipher::consts::{B1, B0};
//use aes::cipher::typenum::{UInt, UTerm};
use wasm_bindgen::prelude::*; 
//use hex_literal::hex;
//use aes::Aes256;
/*use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};*/
use sha2::{Sha256, Digest};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce}; // Or `Aes128GcmSiv`
use aes_gcm_siv::aead::{Aead, NewAead};
//use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
//use aes_gcm::aead::{Aead, NewAead};
use rand::{distributions::Alphanumeric, Rng};
use pbkdf2::{
    password_hash::{PasswordHasher},
    Pbkdf2
};
//use rand_core::{OsRng, block};


#[wasm_bindgen]
pub fn add2numbers(n1:i32,n2:i32)->i32{
    n1+n2
}

#[wasm_bindgen]
pub fn square(n1:i32)->i32{
    n1*n1
}

#[wasm_bindgen]
pub fn hash(mut password:String)->String{
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
    nonce:String, 
}
#[wasm_bindgen]
pub fn new_CryptedMessage(cipherText: Vec<u8>,key: String,nonce:String)->CryptedMessage{
    let crypted_message= CryptedMessage{
        cipherText:cipherText,
        key:key,
        nonce:nonce
    };
    return crypted_message;
}

#[wasm_bindgen]
impl CryptedMessage{
    pub fn get_text(&self)->Vec<u8>{
        self.cipherText.clone()
    }
    pub fn get_key(&self)->String{
        self.key.clone()
    }
    pub fn get_nonce(&self)->String{
        self.nonce.clone()
    }
}

#[wasm_bindgen]
pub fn pbkdf2_derivation(password : String) -> String{
    let password_to_hash = password.as_bytes();
    let salt = "hoBKFfPpeuP5OEO1UxaC42";
    Pbkdf2.hash_password_simple(password_to_hash, salt).unwrap().to_string()
}
#[wasm_bindgen]
pub fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_string(),
        Some((idx, _)) => (&s[..idx]).to_string(),
    }
}
#[wasm_bindgen]
pub fn generateRandomString(size:usize)->String{
    let s: String = rand::thread_rng()
    .sample_iter(&Alphanumeric)
    .take(size)
    .map(char::from)
    .collect();
    return s;
}

#[wasm_bindgen]
pub fn crypt_aes_gcm_siv(message:String)->CryptedMessage{
   

    let rand_key=format!("{}",generateRandomString(32));
    let aeskey = Key::from_slice(rand_key.as_bytes());    
    let cipher = Aes256GcmSiv::new(aeskey);

    let rand_string=format!("{}",generateRandomString(12));
    let nonce = Nonce::from_slice(rand_string.as_bytes()); // 96-bits; unique per message

    let ciphertext = cipher.encrypt(nonce, message.as_ref())
        .expect("encryption failure!");  // NOTE: handle this error to avoid panics!
        println!("encrypted text:{}",format!("{:?}",ciphertext));

    
    let crypted_message = CryptedMessage{
        cipherText: ciphertext,
        //key:reduced_key.to_string(),
        key:rand_key.to_string(),
        nonce: rand_string,
    } ;
    
    return crypted_message;
}
#[wasm_bindgen]
pub fn decrypt_aes_gcm_siv(crypted_message:CryptedMessage)->String{
    let key = Key::from_slice(crypted_message.key.as_bytes());
    let cipher = Aes256GcmSiv::new(key);
    let nonce=Nonce::from_slice(crypted_message.nonce.as_bytes());
    let plaintext = cipher.decrypt(&nonce, crypted_message.cipherText.as_ref())
        .expect("decryption failure!");  // NOTE: handle this error to avoid panics!

    let message = String::from_utf8_lossy(&plaintext);
    println!("Clear text:{}",message);
    return message.to_string();
}


#[wasm_bindgen]
pub fn crypt_aes_key(key:String,password : String)->Vec<u8>{
    let secret_key=String::from(pbkdf2_derivation(password));
    let  split=secret_key.split("$");
    let vec: Vec<&str> = split.collect();
    //println!("{}",secret_key);
    let reduced_key=truncate(vec[4], 32);
    let key_aes = Key::from_slice(reduced_key.as_bytes());
    let cipher = Aes256GcmSiv::new(key_aes);

  //  let mut block=GenericArray::from_slice(key.as_bytes()).clone();
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
   // let mut block2 = block.clone();

    
        let crypted_key = cipher.encrypt(nonce, key.as_ref())
        .expect("encryption failure!");  // NOTE: handle this error to avoid panics!
        // println!("encrypted text:{}",format!("{:?}",ciphertext));
        return crypted_key;

    
    //let new_block=block;
    
}

#[wasm_bindgen]
pub fn decrypt_aes_key(crypted_key:Vec<u8>,password:String)->String{
    let secret_key=String::from(pbkdf2_derivation(password));
    let  split=secret_key.split("$");
    let vec: Vec<&str> = split.collect();
    //println!("{}",secret_key);
    let reduced_key=truncate(vec[4], 32);
    let key_aes = Key::from_slice(reduced_key.as_bytes());
    let cipher = Aes256GcmSiv::new(key_aes);
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let key = cipher.decrypt(nonce, crypted_key.as_ref())
    .expect("decription failure!");  // NOTE: handle this error to avoid panics!
    return String::from_utf8_lossy(&key).to_string();

}
/*
pub fn decrypt_aes_key(crypted_key:String,password : String)->String{
    let secret_key=String::from(pbkdf2_derivation(password));
    let  split=secret_key.split("$");
    let vec: Vec<&str> = split.collect();
    //println!("{}",secret_key);
    let reduced_key=truncate(vec[4], 32);
    let key_aes = GenericArray::from_slice(reduced_key.as_bytes());
    let cipher = Aes256::new(&key_aes);
    let mut block=GenericArray::from_slice(crypted_key.as_bytes());
    cipher.decrypt_block(&mut block);
    return String::from_utf8_lossy(block).to_string();

 }
*/