use crate::{
	ChachaPolyError, XChaCha20, Poly1305,
	chachapoly_ietf::{ CHACHAPOLY_MAX, CHACHAPOLY_KEY, CHACHAPOLY_TAG }
};
use crypto_api::{
	cipher::{ CipherInfo, Cipher, AeadCipher },
	rng::{ SecureRng, SecKeyGen }
};
use std::error::Error;


/// The maximum amount of bytes that can be processed with one key/nonce combination
#[allow(unused)]
pub const XCHACHAPOLY_MAX: usize = CHACHAPOLY_MAX;

/// The size of a XChaChaPoly key (256 bits/32 bytes)
pub const XCHACHAPOLY_KEY: usize = CHACHAPOLY_KEY;
/// The size of a XChaChaPoly nonce (192 bits/24 bytes)
pub const XCHACHAPOLY_NONCE: usize = 24;
/// The size of a XChaChaPoly authentication tag
pub const XCHACHAPOLY_TAG: usize = CHACHAPOLY_TAG;


/// Encrypts `data` in place and authenticates it with `ad` into `tag` using `key` and `nonce`
fn xchachapoly_seal(data: &mut[u8], tag: &mut[u8], ad: &[u8], key: &[u8], nonce: &[u8]) {
	// Encrypt the data
	XChaCha20::xor(key, nonce, 1, data);
	
	// Create the footer
	let mut foot = Vec::with_capacity(16);
	foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
	foot.extend_from_slice(&(data.len() as u64).to_le_bytes());
	
	// Compute the Poly1305 key and the authentication tag
	let mut pkey = vec![0; 32];
	XChaCha20::xor(key, nonce, 0, &mut pkey);
	Poly1305::chachapoly_auth(tag, ad, data, &foot, &pkey);
}
/// Validates `data` with `ad` and decrypts it in place using `key` and `nonce`
fn xchachapoly_open(data: &mut[u8], tag: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
	-> Result<(), Box<dyn Error + 'static>>
{
	// Create the footer
	let mut foot = Vec::with_capacity(16);
	foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
	foot.extend_from_slice(&(data.len() as u64).to_le_bytes());
	
	// Compute the Poly1305 key and the authentication tag
	let (mut pkey, mut vfy_tag) = (vec![0; 32], vec![0; 16]);
	XChaCha20::xor(key, nonce, 0, &mut pkey);
	Poly1305::chachapoly_auth(&mut vfy_tag, ad, data, &foot, &pkey);
	
	// Validate the recomputed and the original tag
	Ok(match eq_ct!(&tag, &vfy_tag) {
		true => XChaCha20::xor(key, nonce, 1, data),
		false => Err(ChachaPolyError::InvalidData)?
	})
}


/// An implementation of XChaChaPoly
pub struct XChachaPoly;
impl XChachaPoly {
	/// Creates a `Cipher` instance with `XChachaPolyIetf` as underlying cipher
	pub fn cipher() -> Box<dyn Cipher> {
		Box::new(Self)
	}
	/// Creates a `AeadCipher` instance with `XChachaPolyIetf` as underlying AEAD cipher
	pub fn aead_cipher() -> Box<dyn AeadCipher> {
		Box::new(Self)
	}
}
impl SecKeyGen for XChachaPoly {
	fn new_sec_key(&self, buf: &mut[u8], rng: &mut dyn SecureRng)
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Validate input
		vfy_keygen!(XCHACHAPOLY_KEY => buf);
		
		// Generate key
		rng.random(&mut buf[..XCHACHAPOLY_KEY])?;
		Ok(XCHACHAPOLY_KEY)
	}
}
impl Cipher for XChachaPoly {
	fn info(&self) -> CipherInfo {
		CipherInfo {
			name: "XChachaPoly", is_otc: true,
			key_len_r: XCHACHAPOLY_KEY..XCHACHAPOLY_KEY,
			nonce_len_r: XCHACHAPOLY_NONCE..XCHACHAPOLY_NONCE,
			aead_tag_len_r: XCHACHAPOLY_TAG..XCHACHAPOLY_TAG
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
impl AeadCipher for XChachaPoly {
	fn seal(&self, buf: &mut[u8], plaintext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_seal!(
			key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
			plaintext_len => [buf, XCHACHAPOLY_MAX]
		);
		
		// Seal the data
		let (data, tag) = buf.split_at_mut(plaintext_len);
		xchachapoly_seal(data, &mut tag[..XCHACHAPOLY_TAG], ad, key, nonce);
		Ok(plaintext_len + XCHACHAPOLY_TAG)
	}
	fn seal_to(&self, buf: &mut[u8], plaintext: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_seal!(
			key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
			plaintext => [buf, XCHACHAPOLY_MAX]
		);
		
		// Copy the plaintext into buf and seal in place
		let (data, tag) = buf.split_at_mut(plaintext.len());
		data.copy_from_slice(plaintext);
		xchachapoly_seal(data, &mut tag[..XCHACHAPOLY_TAG], ad, key, nonce);
		Ok(plaintext.len() + XCHACHAPOLY_TAG)
	}
	
	fn open(&self, buf: &mut[u8], ciphertext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_open!(
			key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
			ciphertext_len => [buf, XCHACHAPOLY_TAG, XCHACHAPOLY_MAX]
		);
		
		// Open the data
		let (data, tag) = buf.split_at_mut(ciphertext_len - XCHACHAPOLY_TAG);
		xchachapoly_open(data, &tag[..XCHACHAPOLY_TAG], ad, key, nonce)?;
		Ok(ciphertext_len - XCHACHAPOLY_TAG)
	}
	fn open_to(&self, buf: &mut[u8], ciphertext: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_open!(
			key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
			ciphertext => [buf, XCHACHAPOLY_TAG, XCHACHAPOLY_MAX]
		);
		
		// Copy the ciphertext into buf and decrypt in place
		let (data, tag) = ciphertext.split_at(ciphertext.len() - XCHACHAPOLY_TAG);
		buf[..data.len()].copy_from_slice(data);
		xchachapoly_open(&mut buf[..data.len()], &tag[..XCHACHAPOLY_TAG], ad, key, nonce)?;
		Ok(ciphertext.len() - XCHACHAPOLY_TAG)
	}
}