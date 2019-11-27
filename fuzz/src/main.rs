use crypto_api_chachapoly::{ ChachaPolyIetf, crypto_api::cipher::AeadCipher };
use crypto_api_osrandom::{ OsRandom, crypto_api::rng::SecureRng };
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use std::{
	thread, error::Error, ops::Range, time::Duration,
	sync::atomic::{ AtomicU64, Ordering::Relaxed }
};


/// An extension trait for `SecureRng`
trait SecureRngExt {
	/// Generates a random `len`-sized vector
	fn random_vec(&mut self, len: usize) -> Result<Vec<u8>, Box<dyn Error + 'static>>;
	/// Computes a random number in `range`
	fn random_range(&mut self, range: Range<u128>) -> Result<u128, Box<dyn Error + 'static>>;
	/// Creates a vec with random sized length within `range` filled with random data
	fn random_len_vec(&mut self, range: Range<usize>) -> Result<Vec<u8>, Box<dyn Error + 'static>>;
}
impl SecureRngExt for Box<dyn SecureRng> {
	fn random_vec(&mut self, len: usize) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
		let mut buf = vec![0; len];
		self.random(&mut buf)?;
		Ok(buf)
	}
	fn random_range(&mut self, range: Range<u128>) -> Result<u128, Box<dyn Error + 'static>> {
		// Compute the bucket size and amount
		let bucket_size = range.end - range.start;
		let bucket_count = u128::max_value() / bucket_size;
		
		// Compute the number
		let mut num = [0; 16];
		loop {
			// Generates a random number
			self.random(&mut num)?;
			let num = u128::from_ne_bytes(num);
			
			// Check if the number falls into the
			if num < bucket_size * bucket_count {
				return Ok((num % bucket_size) + range.start)
			}
		}
	}
	fn random_len_vec(&mut self, range: Range<usize>) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
		let range = (range.start as u128)..(range.end as u128);
		let len = self.random_range(range)? as usize;
		self.random_vec(len)
	}
}


/// An atomic test counter
static COUNTER: AtomicU64 = AtomicU64::new(0);


/// Starts a fuzzer instance that never returns
fn fuzz() -> ! {
	let chachapoly = ChachaPolyIetf;
	let mut rng = OsRandom::secure_rng();
	loop {
		// Create random key and nonce
		let key = chacha20poly1305_ietf::gen_key();
		let nonce = chacha20poly1305_ietf::gen_nonce();
		
		// Create new random plaintext and randomly use additional data
		let plaintext = rng.random_len_vec(0..263).unwrap();
		let ad: &[u8] = match rng.random_range(0..2).unwrap() {
			0 => &plaintext,
			_ => b""
		};
		
		// Seal the data using `crypto_api_chachapoly`
		let mut ct_ours = vec![0u8; plaintext.len() + 16];
		chachapoly.seal_to(
			&mut ct_ours, &plaintext, ad,
			key.as_ref(), nonce.as_ref()
		).unwrap();
		
		// Seal the data using `sodiumoxide`
		let ct_sodium = chacha20poly1305_ietf::seal(
			&plaintext,
			if ad.len() > 0 { Some(ad) } else { None },
			&nonce, &key
		);
		
		// Compare the data
		if ct_ours != ct_sodium {
			eprintln!("FAILURE! This library and libsodium don't match. Inputs:");
			eprintln!("Key: {:?}", key.as_ref());
			eprintln!("Nonce: {:?}", nonce.as_ref());
			eprintln!("Plaintext: {:?}", plaintext);
			eprintln!("Additional data: {:?}", ad);
			eprintln!("Outputs:");
			eprintln!("Ours: {:?}", ct_ours);
			eprintln!("Libsodium: {:?}", ct_sodium);
			panic!("... aborting");
		}
		COUNTER.fetch_add(1, Relaxed);
	}
}


/// Fuzz it!
fn main() {
	for _ in 0..num_cpus::get() {
		thread::spawn(|| fuzz());
	}
	loop {
		thread::sleep(Duration::from_secs(5));
		println!("Performed {} iterations...", COUNTER.load(Relaxed));
	}
}