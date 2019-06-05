use crate::{ChachaPolyError, ChaCha20Ietf, Poly1305 };
use crypto_api::{
	cipher::{ CipherInfo, Cipher, AeadCipher },
	rng::{ SecureRng, SecKeyGen }
};
use std::error::Error;


/// The maximum amount of bytes that can be processed with one key/nonce combination
#[cfg(target_pointer_width = "64")]
const CHACHAPOLY_MAX: usize = (4_294_967_296 - 1) * 64; // (2^32 - 1) * BLOCK_SIZE
/// The maximum amount of bytes that can be processed with one key/nonce combination
#[cfg(target_pointer_width = "32")]
const CHACHAPOLY_MAX: usize = usize::max_value() - 16; // 2^32 - 1 - 16

/// The size of a ChaChaPoly key (256 bits/32 bytes)
const CHACHAPOLY_KEY: usize = 32;
/// The size of a ChaChaPoly nonce (96 bits/12 bytes)
const CHACHAPOLY_NONCE: usize = 12;
/// The size of a ChaChaPoly authentication tag
const CHACHAPOLY_TAG: usize = 16;


/// Encrypts `plaintext_len` bytes in `buf` and authenticates them together with `ad` using `key`
/// and nonce
fn chachapoly_seal(buf: &mut[u8], plaintext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8]) {
	// Split the data and encrypt it
	let (data, tag) = buf.split_at_mut(plaintext_len);
	ChaCha20Ietf::xor(key, nonce, 1, data);
	
	// Create the footer
	let mut foot = Vec::with_capacity(16);
	foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
	foot.extend_from_slice(&(data.len() as u64).to_le_bytes());
	
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
	foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
	foot.extend_from_slice(&(data.len() as u64).to_le_bytes());
	
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
		// Validate input
		vfy_keygen!(CHACHAPOLY_KEY => buf);
		
		// Generate key
		rng.random(&mut buf[..CHACHAPOLY_KEY])?;
		Ok(CHACHAPOLY_KEY)
	}
}
impl Cipher for ChachaPolyIetf {
	fn info(&self) -> CipherInfo {
		CipherInfo {
			name: "ChachaPolyIetf", is_otc: true,
			key_len_r: 32..32, nonce_len_r: 12..12, aead_tag_len_r: 16..16
		}
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
		// Verify input
		vfy_seal!(key, nonce, plaintext_len => buf);
		
		// Seal the data
		chachapoly_seal(buf, plaintext_len, ad, key, nonce);
		Ok(plaintext_len + CHACHAPOLY_TAG)
	}
	fn seal_to(&self, buf: &mut[u8], plaintext: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_seal!(key, nonce, plaintext => buf);
		
		// Copy the plaintext into buf and seal in place
		buf[..plaintext.len()].copy_from_slice(plaintext);
		chachapoly_seal(buf, plaintext.len(), ad, key, nonce);
		Ok(plaintext.len() + CHACHAPOLY_TAG)
	}
	
	fn open(&self, buf: &mut[u8], ciphertext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_open!(key, nonce, ciphertext_len => buf);
		
		// Open the data
		chachapoly_open(buf, ciphertext_len, ad, key, nonce)?;
		Ok(ciphertext_len - CHACHAPOLY_TAG)
	}
	fn open_to(&self, buf: &mut[u8], ciphertext: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_open!(key, nonce, ciphertext => buf);
		
		// Copy the ciphertext into buf and decrypt in place
		buf[..ciphertext.len()].copy_from_slice(ciphertext);
		chachapoly_open(buf, ciphertext.len(), ad, key, nonce)?;
		Ok(ciphertext.len() - CHACHAPOLY_TAG)
	}
}