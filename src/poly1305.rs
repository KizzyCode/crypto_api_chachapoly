use crypto_api::{
	mac::{ MacInfo, Mac },
	rng::{ SecureRng, SecKeyGen }
};
use std::{ cmp::min, error::Error };


/// The size of a Poly1305 key (256 bits/32 bytes)
const POLY1305_KEY: usize = 32;
/// The size of a ChaChaPoly authentication tag
const POLY1305_TAG: usize = 16;


/// Loads `key` into `r` and `s` and computes the key-based multipliers into `u`
fn poly1305_init(r: &mut[u32], s: &mut[u32], u: &mut[u32], key: &[u8]) {
	// Load key
	r[0] = and!(shr!(read32_le!(&key[ 0..]), 0), 0x03FFFFFF);
	r[1] = and!(shr!(read32_le!(&key[ 3..]), 2), 0x03FFFF03);
	r[2] = and!(shr!(read32_le!(&key[ 6..]), 4), 0x03FFC0FF);
	r[3] = and!(shr!(read32_le!(&key[ 9..]), 6), 0x03F03FFF);
	r[4] = and!(shr!(read32_le!(&key[12..]), 8), 0x000FFFFF);
	
	s[0] = read32_le!(&key[16..]);
	s[1] = read32_le!(&key[20..]);
	s[2] = read32_le!(&key[24..]);
	s[3] = read32_le!(&key[28..]);
	
	// Pre-compute multipliers
	u[0] = 0;
	u[1] = mul!(r[1], 5);
	u[2] = mul!(r[2], 5);
	u[3] = mul!(r[3], 5);
	u[4] = mul!(r[4], 5);
}
/// Updates `a` with `data` using the key `r` and the multipliers `u`
///
/// _Warning: This implementation will pad __ANY__ incomplete block with `0` bytes; the `is_last`
/// switch indicates where the high bit should be appended_
fn poly1305_update(a: &mut[u32], r: &[u32], u: &[u32], mut data: &[u8], is_last: bool) {
	// Prepare buffer and `w` to avoid unnecessary reallocations
	let mut buf = vec![0; 16];
	let mut w = vec![0; 5];
	
	// Process the data
	while !data.is_empty() {
		// Copy data into buf and append `0x01` byte to an incomplete block last block if necessary
		let buf_len = min(data.len(), buf.len());
		if buf_len < 16 {
			buf.copy_from_slice(&[0; 16]);
			if is_last { buf[buf_len] = 0x01 }
		}
		buf[..buf_len].copy_from_slice(&data[..buf_len]);
		
		// Decode the next block into the accumulator and apply the "high bit" if appropriate
		a[0] = add!(a[0], and!(shr!(read32_le!(&buf[ 0..]), 0), 0x03FFFFFF));
		a[1] = add!(a[1], and!(shr!(read32_le!(&buf[ 3..]), 2), 0x03FFFFFF));
		a[2] = add!(a[2], and!(shr!(read32_le!(&buf[ 6..]), 4), 0x03FFFFFF));
		a[3] = add!(a[3], and!(shr!(read32_le!(&buf[ 9..]), 6), 0x03FFFFFF));
		a[4] = match buf_len < 16 && is_last {
			true  => add!(a[4],  or!(shr!(read32_le!(&buf[12..]), 8), 0x00000000)),
			false => add!(a[4],  or!(shr!(read32_le!(&buf[12..]), 8), 0x01000000))
		};
		
		
		/// Converts `$a` and `$b` to `u64`s and multiplies them without overflow-trap
		macro_rules! m {
			($a:expr, $b:expr) => ({ mul!($a as u64, $b as u64) })
		}
		// Multiply
		w[0] = add!(m!(a[0], r[0]), m!(a[1], u[4]), m!(a[2], u[3]), m!(a[3], u[2]), m!(a[4], u[1]));
		w[1] = add!(m!(a[0], r[1]), m!(a[1], r[0]), m!(a[2], u[4]), m!(a[3], u[3]), m!(a[4], u[2]));
		w[2] = add!(m!(a[0], r[2]), m!(a[1], r[1]), m!(a[2], r[0]), m!(a[3], u[4]), m!(a[4], u[3]));
		w[3] = add!(m!(a[0], r[3]), m!(a[1], r[2]), m!(a[2], r[1]), m!(a[3], r[0]), m!(a[4], u[4]));
		w[4] = add!(m!(a[0], r[4]), m!(a[1], r[3]), m!(a[2], r[2]), m!(a[3], r[1]), m!(a[4], r[0]));
		
		
		// Perform some modular reduction to avoid carry-overflows
		let mut c;
		c = shr!(w[0], 26); a[0] = and!(w[0] as u32, 0x3FFFFFF); w[1] = add!(w[1], c);
		c = shr!(w[1], 26); a[1] = and!(w[1] as u32, 0x3FFFFFF); w[2] = add!(w[2], c);
		c = shr!(w[2], 26); a[2] = and!(w[2] as u32, 0x3FFFFFF); w[3] = add!(w[3], c);
		c = shr!(w[3], 26); a[3] = and!(w[3] as u32, 0x3FFFFFF); w[4] = add!(w[4], c);
		c = shr!(w[4], 26); a[4] = and!(w[4] as u32, 0x3FFFFFF);
		
		a[0] = add!(a[0], mul!(c as u32, 5));
		a[1] = add!(a[1], shr!(a[0], 26));
		a[0] = and!(a[0], 0x3FFFFFF);
		
		// Adjust data
		data = &data[buf_len..]
	}
}
/// Finalizes the authentication into `tag` using the state `a` and `key`
fn poly1305_finish(tag: &mut[u8], a: &mut[u32], s: &[u32]) {
	// Finalize modular reduction
	let mut c;
	c = shr!(a[1], 26); a[1] = and!(a[1], 0x3ffffff); a[2] = add!(a[2], c);
	c = shr!(a[2], 26); a[2] = and!(a[2], 0x3ffffff); a[3] = add!(a[3], c);
	c = shr!(a[3], 26); a[3] = and!(a[3], 0x3ffffff); a[4] = add!(a[4], c);
	c = shr!(a[4], 26); a[4] = and!(a[4], 0x3ffffff); a[0] = add!(a[0], mul!(c, 5));
	c = shr!(a[0], 26); a[0] = and!(a[0], 0x3ffffff); a[1] = add!(a[1], c);
	
	// Reduce again if our value is in `(2^130-5, 2^130]`
	let mut mux = gt!(a[0], 0x03FFFFFAu32);
	for i in 1..5 { mux = and!(mux, eq!(a[i], 0x03FFFFFF)) }
	
	c = 5;
	for i in 0..5 {
		let mut t = add!(a[i], c);
		c = shr!(t, 26);
		t = and!(t, 0x03FFFFFF);
		a[i] = mux_bool!(mux, t, a[i]);
	}
	
	// Convert the accumulator back to 32bit words and add the second half of `key` modulo `2^128`
	let mut word;
	word = add!(a[0] as u64,    shl!(a[1] as u64, 26), s[0] as u64);
	write32_le!(word as u32 => &mut tag[0..]);
	
	word = add!(shr!(word, 32), shl!(a[2] as u64, 20), s[1] as u64);
	write32_le!(word as u32 => &mut tag[4..]);
	
	word = add!(shr!(word, 32), shl!(a[3] as u64, 14), s[2] as u64);
	write32_le!(word as u32 => &mut tag[8..]);
	
	word = add!(shr!(word, 32) as u32, shl!(a[4],  8), s[3]) as u64;
	write32_le!(word as u32 => &mut tag[12..]);
}


/// An implementation of [Poly1305](https://tools.ietf.org/html/rfc8439)
pub struct Poly1305;
impl Poly1305 {
	/// Creates a `Mac` instance with `Poly1305` as underlying algorithm
	pub fn mac() -> Box<dyn Mac> {
		Box::new(Self)
	}
	
	/// A helper function for the ChachaPoly-IETF AEAD construction
	pub(in crate) fn chachapoly_auth(tag: &mut[u8], ad: &[u8], data: &[u8], foot: &[u8], key: &[u8])
	{
		// Init Poly1305
		let (mut r, mut s, mut u, mut a) = (vec![0; 5], vec![0; 4], vec![0; 5], vec![0; 5]);
		poly1305_init(&mut r, &mut s, &mut u, key);
		
		// Process AD, data and the footer
		poly1305_update(&mut a, &r, &u, ad, false);
		poly1305_update(&mut a, &r, &u, data, false);
		poly1305_update(&mut a, &r, &u, foot, true);
		poly1305_finish(tag, &mut a, &mut s);
	}
}
impl SecKeyGen for Poly1305 {
	fn new_sec_key(&self, buf: &mut[u8], rng: &mut SecureRng)
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_keygen!(POLY1305_KEY => buf);
		
		// Generate key
		rng.random(&mut buf[..POLY1305_KEY])?;
		Ok(POLY1305_KEY)
	}
}
impl Mac for Poly1305 {
	fn info(&self) -> MacInfo {
		MacInfo {
			name: "Poly1305", is_otm: true,
			mac_len: POLY1305_TAG,
			mac_len_r: POLY1305_TAG..POLY1305_TAG,
			key_len_r: POLY1305_KEY..POLY1305_KEY
		}
	}
	
	fn auth(&self, buf: &mut[u8], data: &[u8], key: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>
	{
		// Verify input
		vfy_auth!(key, => buf);
		
		// Authenticate data
		let (mut r, mut s, mut u, mut a) =
			(vec![0; 5], vec![0; 4], vec![0; 5], vec![0; 5]);
		poly1305_init(&mut r, &mut s, &mut u, key);
		poly1305_update(&mut a, &r, &u, data, true);
		poly1305_finish(buf, &mut a, &mut s);
		
		Ok(POLY1305_TAG)
	}
}