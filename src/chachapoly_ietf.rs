use crate::{ ChachaPolyError, ChaCha20Ietf, Poly1305 };
use crypto_api::{
	cipher::{ CipherInfo, Cipher, AeadCipher },
	rng::{ SecureRng, SecKeyGen }
};
use std::error::Error;


/// The maximum amount of bytes that can be processed with one key/nonce combination
#[cfg(target_pointer_width = "64")]
pub const CHACHAPOLY_MAX: usize = (4_294_967_296 - 1) * 64; // (2^32 - 1) * BLOCK_SIZE
/// The maximum amount of bytes that can be processed with one key/nonce combination
#[cfg(target_pointer_width = "32")]
pub const CHACHAPOLY_MAX: usize = usize::max_value() - 16; // 2^32 - 1 - 16

/// The size of a ChaChaPoly key (256 bits/32 bytes)
pub const CHACHAPOLY_KEY: usize = 32;
/// The size of a ChaChaPoly nonce (96 bits/12 bytes)
pub const CHACHAPOLY_NONCE: usize = 12;
/// The size of a ChaChaPoly authentication tag
pub const CHACHAPOLY_TAG: usize = 16;


/// Encrypts `data` in place and authenticates it with `ad` into `tag` using `key` and `nonce`
pub fn chachapoly_seal(data: &mut[u8], tag: &mut[u8], ad: &[u8], key: &[u8], nonce: &[u8]) {
	// Encrypt the data
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
/// Validates `data` with `ad` and decrypts it in place using `key` and `nonce`
pub fn chachapoly_open(data: &mut[u8], tag: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
	-> Result<(), Box<dyn Error + 'static>>
{
	// Create the footer
	let mut foot = Vec::with_capacity(16);
	foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
	foot.extend_from_slice(&(data.len() as u64).to_le_bytes());
	
	// Compute the Poly1305 key and the authentication tag
	let (mut pkey, mut vfy_tag) = (vec![0; 32], vec![0; 16]);
	ChaCha20Ietf::xor(key, nonce, 0, &mut pkey);
	Poly1305::chachapoly_auth(&mut vfy_tag, ad, data, &foot, &pkey);
	
	// Validate the recomputed and the original tag
	Ok(match eq_ct!(&tag, &vfy_tag) {
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
	fn new_sec_key(&self, buf: &mut[u8], rng: &mut dyn SecureRng)
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
			key_len_r: CHACHAPOLY_KEY..(CHACHAPOLY_KEY + 1),
			nonce_len_r: CHACHAPOLY_NONCE..(CHACHAPOLY_NONCE + 1),
			aead_tag_len_r: CHACHAPOLY_TAG..(CHACHAPOLY_TAG + 1)
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
		vfy_seal!(
			key => [CHACHAPOLY_KEY], nonce => [CHACHAPOLY_NONCE],
			plaintext_len => [buf, CHACHAPOLY_MAX]
		);
		
		// Seal the data
		let (data, tag) = buf.split_at_mut(plaintext_len);
		chachapoly_seal(data, &mut tag[..CHACHAPOLY_TAG], ad, key, nonce);
		Ok(plaintext_len + CHACHAPOLY_TAG)
	}
	fn seal_to(&self, buf: &mut[u8], plaintext: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_seal!(
			key => [CHACHAPOLY_KEY], nonce => [CHACHAPOLY_NONCE],
			plaintext => [buf, CHACHAPOLY_MAX]
		);
		
		// Copy the plaintext into buf and seal in place
		let (data, tag) = buf.split_at_mut(plaintext.len());
		data.copy_from_slice(plaintext);
		chachapoly_seal(data, &mut tag[..CHACHAPOLY_TAG], ad, key, nonce);
		Ok(plaintext.len() + CHACHAPOLY_TAG)
	}
	
	fn open(&self, buf: &mut[u8], ciphertext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_open!(
			key => [CHACHAPOLY_KEY], nonce => [CHACHAPOLY_NONCE],
			ciphertext_len => [buf, CHACHAPOLY_TAG, CHACHAPOLY_MAX]
		);
		
		// Open the data
		let (data, tag) = buf.split_at_mut(ciphertext_len - CHACHAPOLY_TAG);
		chachapoly_open(data, &tag[..CHACHAPOLY_TAG], ad, key, nonce)?;
		Ok(ciphertext_len - CHACHAPOLY_TAG)
	}
	fn open_to(&self, buf: &mut[u8], ciphertext: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_open!(
			key => [CHACHAPOLY_KEY], nonce => [CHACHAPOLY_NONCE],
			ciphertext => [buf, CHACHAPOLY_TAG, CHACHAPOLY_MAX]
		);
		
		// Copy the ciphertext into buf and decrypt in place
		let (data, tag) = ciphertext.split_at(ciphertext.len() - CHACHAPOLY_TAG);
		buf[..data.len()].copy_from_slice(data);
		chachapoly_open(&mut buf[..data.len()], &tag[..CHACHAPOLY_TAG], ad, key, nonce)?;
		Ok(ciphertext.len() - CHACHAPOLY_TAG)
	}
}