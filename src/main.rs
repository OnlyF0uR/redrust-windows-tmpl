use windows::core::Result;

pub mod fs;
pub mod rsa;

fn main() -> Result<()> {
    let (h_key, pub_key, priv_key) = rsa::generate_rsa_keypair(2048)?;
    println!("Public key: {:?}", pub_key);
    println!("Private key: {:?}", priv_key);

    let input = "!dlrow ,olleH";

    // Encrypt
    let ed = rsa::encrypt(h_key, input.as_bytes(), 2048)?;
    // Write
    fs::cw_file("encrypted.txt", &ed)?;
    // Read
    let file_cnt = fs::r_file("encrypted.txt")?;
    // Decrypt
    let dd = rsa::decrypt(h_key, &file_cnt)?;

    println!("{:?}", input);
    println!("{:?}", String::from_utf8(dd)?);

    Ok(())
}
