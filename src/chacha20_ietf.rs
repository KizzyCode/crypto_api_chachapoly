use crate::core::chacha20::chacha20_ietf_block;
use crypto_api::{
    cipher::{ CipherInfo, Cipher },
    rng::{ SecureRng, SecKeyGen }
};
use std::{ cmp::min, error::Error };


/// The maximum amount of bytes that can be processed with one key/nonce combination
#[cfg(target_pointer_width = "64")]
pub const CHACHA20_MAX: usize = 4_294_967_296 * 64; // 2^32 * BLOCK_SIZE
/// The maximum amount of bytes that can be processed with one key/nonce combination
#[cfg(target_pointer_width = "32")]
pub const CHACHA20_MAX: usize = usize::max_value(); // 2^32 - 1


/// The size of a ChaCha20 key (256 bits/32 bytes)
pub const CHACHA20_KEY: usize = 32;
/// The size of a ChaCha20 nonce (96 bits/12 bytes)
pub const CHACHA20_NONCE: usize = 12;


/// An implementation of [ChaCha20 (IETF-version)](https://tools.ietf.org/html/rfc8439)
pub struct ChaCha20Ietf;
impl ChaCha20Ietf {
    /// Creates a `Cipher` instance with `ChaCha20Ietf` as underlying cipher
    pub fn cipher() -> Box<dyn Cipher> {
        Box::new(Self)
    }
    
    /// XORs the bytes in `data` with the ChaCha20 keystream for `key` and `nonce` starting at the
    /// `n`th block
    ///
    /// ## Warning:
    /// This function panics if
    ///  - `key` is smaller or larger than 32 bytes/256 bits
    ///  - `nonce` is smaller or larger than 12 bytes/96 bits
    ///  - `n` exceeds `2^32 - 1` (which means that `data` must be smaller than `(2^32 - n) * 64`)
    ///
    /// __Consider using the `crypto_api`-interface instead of calling this function directly__
    pub fn xor(key: &[u8], nonce: &[u8], mut n: u32, mut data: &mut[u8]) {
        // Verify input
        assert_eq!(CHACHA20_KEY, key.len());
        assert_eq!(CHACHA20_NONCE, nonce.len());
        
        // XOR `data`
        let mut buf = vec![0; 64];
        while !data.is_empty() {
            // Compute next block
            chacha20_ietf_block(key, nonce, n, &mut buf);
            n = n.checked_add(1).expect("The ChaCha20-IETF block counter must not exceed 2^32 - 1");
            
            // Xor block
            let to_xor = min(data.len(), buf.len());
            (0..to_xor).for_each(|i| data[i] = xor!(data[i], buf[i]));
            data = &mut data[to_xor..];
        }
    }
}
impl SecKeyGen for ChaCha20Ietf {
    fn new_sec_key(&self, buf: &mut[u8], rng: &mut dyn SecureRng) -> Result<usize, Box<dyn Error + 'static>> {
        // Verify input
        vfy_keygen!(CHACHA20_KEY => buf);
        
        // Generate key
        rng.random(&mut buf[..CHACHA20_KEY])?;
        Ok(CHACHA20_KEY)
    }
}
impl Cipher for ChaCha20Ietf {
    fn info(&self) -> CipherInfo {
        CipherInfo {
            name: "ChaCha20Ietf", is_otc: true,
            key_len_r: CHACHA20_KEY..(CHACHA20_KEY + 1),
            nonce_len_r: CHACHA20_NONCE..(CHACHA20_NONCE + 1),
            aead_tag_len_r: 0..(0 + 1)
        }
    }
    
    fn encrypted_len_max(&self, plaintext_len: usize) -> usize {
        plaintext_len
    }
    
    fn encrypt(&self, buf: &mut[u8], plaintext_len: usize, key: &[u8], nonce: &[u8])
        -> Result<usize, Box<dyn Error + 'static>>
    {
        // Verify input
        vfy_enc!(
            key => [CHACHA20_KEY], nonce => [CHACHA20_NONCE],
            plaintext_len => [buf, CHACHA20_MAX]
        );
        
        // Encrypt the data
        Self::xor(key, nonce, 0, &mut buf[..plaintext_len]);
        Ok(plaintext_len)
    }
    fn encrypt_to(&self, buf: &mut[u8], plaintext: &[u8], key: &[u8], nonce: &[u8])
        -> Result<usize, Box<dyn Error + 'static>>
    {
        // Verify input
        vfy_enc!(
            key => [CHACHA20_KEY], nonce => [CHACHA20_NONCE],
            plaintext => [buf, CHACHA20_MAX]
        );
        
        // Fill `buf` and encrypt the data in place
        buf[..plaintext.len()].copy_from_slice(plaintext);
        Self::xor(key, nonce, 0, &mut buf[..plaintext.len()]);
        Ok(plaintext.len())
    }
    
    fn decrypt(&self, buf: &mut[u8], ciphertext_len: usize, key: &[u8], nonce: &[u8])
        -> Result<usize, Box<dyn Error + 'static>>
    {
        // Verify input
        vfy_dec!(
            key => [CHACHA20_KEY], nonce => [CHACHA20_NONCE],
            ciphertext_len => [buf, CHACHA20_MAX]
        );
        
        // Encrypt the data
        Self::xor(key, nonce, 0, &mut buf[..ciphertext_len]);
        Ok(ciphertext_len)
    }
    fn decrypt_to(&self, buf: &mut[u8], ciphertext: &[u8], key: &[u8], nonce: &[u8])
        -> Result<usize, Box<dyn Error + 'static>>
    {
        // Verify input
        vfy_dec!(
            key => [CHACHA20_KEY], nonce => [CHACHA20_NONCE],
            ciphertext => [buf, CHACHA20_MAX]
        );
        
        // Fill `buf` and encrypt the data in place
        buf[..ciphertext.len()].copy_from_slice(ciphertext);
        Self::xor(key, nonce, 0, &mut buf[..ciphertext.len()]);
        Ok(ciphertext.len())
    }
}
