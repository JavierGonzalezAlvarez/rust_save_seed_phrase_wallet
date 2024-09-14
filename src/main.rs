use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose, Engine};
use std::fs::File;
use std::io::{self, Write, Read};
use rpassword::read_password;


type Aes256Cbc = Cbc<Aes256, Pkcs7>;


fn main() {
    println!("¿Do you want to (1) save or (2) recover words? write 1 or 2:");
    let mut option = String::new();
    io::stdin().read_line(&mut option).expect("Error, we could not read the option");

    match option.trim() {
        "1" => save_words(),
        "2" => retrieve_words(),
        _ => println!("Opción no válida. Debes escribir 1 o 2."),
    }
}

fn save_words() {
    let words = prompt_for_words();
    let password = prompt_for_password();
    let combined_words = words.join(" ");
    let password_hash = generate_hash(&password);
    let encrypted_words = encrypt(&combined_words, &password);
    save_to_file(&password_hash, &encrypted_words);
}

fn retrieve_words() {
    let password = prompt_for_password();

    if let Some((stored_hash, encrypted_words)) = get_stored_data() {
        let generated_hash = generate_hash(&password);

        if stored_hash == generated_hash {
            if let Some(decrypted_words) = decrypt(&encrypted_words, &password) {
                println!("words recovered: {}", decrypted_words);
            } else {
                println!("Error decipher words");
            }
        } else {
            println!("wrong password");
        }
    } else {
        println!("file not found.");
    }
}

fn prompt_for_words() -> Vec<String> {
    let mut words = Vec::new();
    for i in 1..=12 {
        println!("Input a word {}:", i);
        let mut word = String::new();
        io::stdin().read_line(&mut word).expect("Error when reading a word");
        words.push(word.trim().to_string());
    }
    words
}

fn prompt_for_password() -> String {
    println!("Input the password:");
    let password = read_password().expect("Error when reading password");
    password
}

fn generate_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn encrypt(plain_text: &str, key: &str) -> String {
    let key_bytes = key.as_bytes();

    let mut key_32_bytes = vec![0u8; 32];
    if key_bytes.len() >= 32 {
        key_32_bytes.copy_from_slice(&key_bytes[0..32]);
    } else {
        key_32_bytes[..key_bytes.len()].copy_from_slice(key_bytes);
    }

    let iv = [0u8; 16]; 

    let cipher = Aes256Cbc::new_from_slices(&key_32_bytes, &iv).unwrap();
    let ciphertext = cipher.encrypt_vec(plain_text.as_bytes());

    general_purpose::STANDARD.encode(&ciphertext)
}

fn decrypt(cipher_text: &str, key: &str) -> Option<String> {
    let key_bytes = key.as_bytes();

    let mut key_32_bytes = vec![0u8; 32];
    if key_bytes.len() >= 32 {
        key_32_bytes.copy_from_slice(&key_bytes[0..32]);
    } else {
        key_32_bytes[..key_bytes.len()].copy_from_slice(key_bytes);
    }

    let iv = [0u8; 16]; 

    let cipher = Aes256Cbc::new_from_slices(&key_32_bytes, &iv).unwrap();
    let decoded_ciphertext = general_purpose::STANDARD.decode(cipher_text).ok()?;

    let decrypted_data = cipher.decrypt_vec(&decoded_ciphertext).ok()?;
    String::from_utf8(decrypted_data).ok()
}

fn save_to_file(hash: &str, encrypted_text: &str) {
    let mut file = File::create("data.txt").expect("we could not create the file");
    writeln!(file, "{}", hash).expect("we could not write the hash - password");
    writeln!(file, "{}", encrypted_text).expect("we could not write the cipher words");
    println!("Data save properly in file .txt");
}

fn get_stored_data() -> Option<(String, String)> {
    let mut file = File::open("data.txt").ok()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).ok()?;

    let mut lines = contents.lines();
    let hash = lines.next()?.to_string();
    let encrypted_text = lines.next()?.to_string();

    Some((hash, encrypted_text))
}
