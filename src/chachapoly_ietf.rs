use crate::{ChachaPolyError, ChaCha20Ietf, Poly1305 };
use crypto_api::{
	cipher::{ CipherInfo, Cipher, AeadCipher },
	rng::{ SecureRng, SecKeyGen }
};
use std::error::Error;


/// The maximum amount of bytes that can be processed with one key/nonce combination
#[cfg(target_pointer_width = "64")]
const CHACHAPOLY_MAX: usize = 4_294_967_296 * 64; // 2^32 * BLOCK_SIZE
/// The maximum amount of bytes that can be processed with one key/nonce combination
#[cfg(target_pointer_width = "32")]
const CHACHAPOLY_MAX: usize = usize::max_value(); // 2^32 - 1


/// Encrypts `plaintext_len` bytes in `buf` and authenticates them together with `ad` using `key`
/// and nonce
fn chachapoly_seal(buf: &mut[u8], plaintext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8]) {
	// Split the data and encrypt it
	let (data, tag) = buf.split_at_mut(plaintext_len);
	ChaCha20Ietf::xor(key, nonce, 1, data);
	
	// Create the footer
	let mut foot = Vec::with_capacity(16);
	foot.extend_from_slice(&ad.len().to_le_bytes());
	foot.extend_from_slice(&data.len().to_le_bytes());
	
	// Compute the Poly1305 key and the authentication tag
	let mut pkey = vec![0; 32];
	ChaCha20Ietf::xor(key, nonce, 0, &mut pkey);
	Poly1305::chachapoly_auth(tag, ad, data, &foot, &pkey);
}
/// Validates `ciphertext_len` bytes in `buf` together with `ad` and decrypts the data in `buf`
/// using `key` and nonce
fn chachapoly_open(buf: &mut[u8], ciphertext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8])
	-> Result<(), Box<dyn Error + 'static>>
{
	// Split `buf`
	let (data, org) = buf.split_at_mut(ciphertext_len - 16);
	
	// Create the footer
	let mut foot = Vec::with_capacity(16);
	foot.extend_from_slice(&ad.len().to_le_bytes());
	foot.extend_from_slice(&data.len().to_le_bytes());
	
	// Compute the Poly1305 key and the authentication tag
	let (mut pkey, mut tag) = (vec![0; 32], vec![0; 16]);
	ChaCha20Ietf::xor(key, nonce, 0, &mut pkey);
	Poly1305::chachapoly_auth(&mut tag, ad, data, &foot, &pkey);
	
	// Validate the recomputed and the original tag
	Ok(match eq_ct!(&tag, &org[..16]) {
		true => ChaCha20Ietf::xor(key, nonce, 1, data),
		false => Err(ChachaPolyError::InvalidData)?
	})
}


/// An implementation of the
/// [ChachaPoly-IETF AEAD-construction](https://tools.ietf.org/html/rfc8439)
pub struct ChachaPolyIetf;
impl ChachaPolyIetf {
	/// Creates a `Cipher` instance with `ChachaPolyIetf` as underlying cipher
	pub fn cipher() -> Box<dyn Cipher> {
		Box::new(Self)
	}
	/// Creates a `AeadCipher` instance with `ChachaPolyIetf` as underlying AEAD cipher
	pub fn aead_cipher() -> Box<dyn AeadCipher> {
		Box::new(Self)
	}
}
impl SecKeyGen for ChachaPolyIetf {
	fn new_sec_key(&self, buf: &mut[u8], rng: &mut SecureRng)
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Validate buffer and generate key
		if buf.len() < 32 { Err(ChachaPolyError::ApiMisuse("Buffer is too small"))? }
		rng.random(&mut buf[..32])?;
		Ok(32)
	}
}
impl Cipher for ChachaPolyIetf {
	fn info(&self) -> CipherInfo {
		CipherInfo{ name: "ChachaPolyIetf", key_len: 32, nonce_len: 12, aead_tag_len: Some(16) }
	}
	
	fn encrypted_len_max(&self, plaintext_len: usize) -> usize {
		plaintext_len + 16
	}
	
	fn encrypt(&self, buf: &mut[u8], plaintext_len: usize, key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		self.seal(buf, plaintext_len, &[], key, nonce)
	}
	fn encrypt_to(&self, buf: &mut[u8], plaintext: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		self.seal_to(buf, plaintext, &[], key, nonce)
	}
	
	fn decrypt(&self, buf: &mut[u8], ciphertext_len: usize, key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		self.open(buf, ciphertext_len, &[], key, nonce)
	}
	fn decrypt_to(&self, buf: &mut[u8], ciphertext: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		self.open_to(buf, ciphertext, &[], key, nonce)
	}
}
impl AeadCipher for ChachaPolyIetf {
	fn seal(&self, buf: &mut[u8], plaintext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Check input
		if key.len() != 32 { Err(ChachaPolyError::ApiMisuse("Invalid key length"))? }
		if nonce.len() != 12 { Err(ChachaPolyError::ApiMisuse("Invalid nonce length"))? }
		
		if plaintext_len > CHACHAPOLY_MAX { Err(ChachaPolyError::ApiMisuse("Too much data"))? }
		if plaintext_len + 16 > buf.len() {
			Err(ChachaPolyError::ApiMisuse("Buffer is too small"))?
		}
		
		// Seal the data
		chachapoly_seal(buf, plaintext_len, ad, key, nonce);
		Ok(plaintext_len + 16)
	}
	fn seal_to(&self, buf: &mut[u8], plaintext: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Check input and copy plaintext into buf and encrypt in place
		if plaintext.len() > buf.len() { Err(ChachaPolyError::ApiMisuse("Buffer is too small"))? }
		
		buf[..plaintext.len()].copy_from_slice(plaintext);
		self.seal(buf, plaintext.len(), ad, key, nonce)
	}
	
	fn open(&self, buf: &mut[u8], ciphertext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Check input
		if key.len() != 32 { Err(ChachaPolyError::ApiMisuse("Invalid key length"))? }
		if nonce.len() != 12 { Err(ChachaPolyError::ApiMisuse("Invalid nonce length"))? }
		
		if ciphertext_len < 16 { Err(ChachaPolyError::InvalidData)? }
		if ciphertext_len > CHACHAPOLY_MAX + 16 { Err(ChachaPolyError::InvalidData)? }
		if ciphertext_len > buf.len() { Err(ChachaPolyError::ApiMisuse("Buffer is too small"))? }
		
		// Open the data
		chachapoly_open(buf, ciphertext_len, ad, key, nonce)?;
		Ok(ciphertext_len - 16)
	}
	fn open_to(&self, buf: &mut[u8], ciphertext: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Check input and copy ciphertext into buf and decrypt in place
		if ciphertext.len() > buf.len() { Err(ChachaPolyError::ApiMisuse("Buffer is too small"))? }
		
		buf[..ciphertext.len()].copy_from_slice(ciphertext);
		self.open(buf, ciphertext.len(), ad, key, nonce)
	}
}