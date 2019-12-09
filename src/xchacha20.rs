use crate::{
	chacha20_ietf::CHACHA20_KEY,
	core::chacha20::{ hchacha20_hash, chacha20_block }
};
use crypto_api::{
	cipher::{ CipherInfo, Cipher },
	rng::{ SecureRng, SecKeyGen }
};
use std::{ cmp::min, error::Error };


/// The maximum amount of bytes that can be processed by this implementation with one key/nonce
/// combination
pub const XCHACHA20_MAX: usize = usize::max_value();

/// The size of a XChaCha20 key (256 bits/32 bytes)
pub const XCHACHA20_KEY: usize = CHACHA20_KEY;
/// The size of a XChaCha20 nonce (192 bits/24 bytes)
pub const XCHACHA20_NONCE: usize = 24;


/// An implementation of XChaCha20
pub struct XChaCha20;
impl XChaCha20 {
	/// Creates a `Cipher` instance with `XChaCha20` as underlying cipher
	pub fn cipher() -> Box<dyn Cipher> {
		Box::new(Self)
	}
	
	/// XORs the bytes in `data` with the XChaCha20 keystream for `key` and `nonce` starting at the
	/// `n`th block
	///
	/// ## Warning:
	/// This function panics if
	///  - `key` is smaller or larger than 32 bytes/256 bits
	///  - `nonce` is smaller or larger than 24 bytes/192 bits
	///  - `n` exceeds `2^64 - 1` (which means that `data` must be smaller than `(2^64 - n) * 64`)
	///
	/// __Consider using the `crypto_api`-interface instead of calling this function directly__
	pub fn xor(key: &[u8], nonce: &[u8], mut n: u64, mut data: &mut[u8]) {
		// Verify input
		assert_eq!(XCHACHA20_KEY, key.len());
		assert_eq!(XCHACHA20_NONCE, nonce.len());
		
		// Derive key
		let (x_nonce, nonce) = nonce.split_at(16);
		let mut x_key = vec![0; 32];
		hchacha20_hash(key, x_nonce, &mut x_key);
		
		// XOR `data`
		let mut buf = vec![0; 64];
		while !data.is_empty() {
			// Compute next block
			chacha20_block(&x_key, nonce, n, &mut buf);
			n = n.checked_add(1).expect("The ChaCha20 block counter must not exceed 2^64 - 1");
			
			// Xor block
			let to_xor = min(data.len(), buf.len());
			(0..to_xor).for_each(|i| data[i] = xor!(data[i], buf[i]));
			data = &mut data[to_xor..];
		}
	}
}
impl SecKeyGen for XChaCha20 {
	fn new_sec_key(&self, buf: &mut[u8], rng: &mut dyn SecureRng)
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_keygen!(XCHACHA20_KEY => buf);
		
		// Generate key
		rng.random(&mut buf[..XCHACHA20_KEY])?;
		Ok(XCHACHA20_KEY)
	}
}
impl Cipher for XChaCha20 {
	fn info(&self) -> CipherInfo {
		CipherInfo {
			name: "XChaCha20", is_otc: true,
			key_len_r: XCHACHA20_KEY..XCHACHA20_KEY,
			nonce_len_r: XCHACHA20_NONCE..XCHACHA20_NONCE,
			aead_tag_len_r: 0..0
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
			key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
			plaintext_len => [buf, XCHACHA20_MAX]
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
			key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
			plaintext => [buf, XCHACHA20_MAX]
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
			key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
			ciphertext_len => [buf, XCHACHA20_MAX]
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
			key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
			ciphertext => [buf, XCHACHA20_MAX]
		);
		
		// Fill `buf` and encrypt the data in place
		buf[..ciphertext.len()].copy_from_slice(ciphertext);
		Self::xor(key, nonce, 0, &mut buf[..ciphertext.len()]);
		Ok(ciphertext.len())
	}
}
