use crypto_api_chachapoly::{ ChachaPolyIetf, XChachaPoly, crypto_api::cipher::AeadCipher };
use crypto_api_osrandom::{ OsRandom, crypto_api::rng::SecureRng };
use sodiumoxide::crypto::aead::{ chacha20poly1305_ietf, xchacha20poly1305_ietf };
use std::{
	thread, error::Error, ops::Range, time::Duration,
	sync::atomic::{ AtomicU64, Ordering::Relaxed }
};


/// An atomic test counter
static COUNTER: AtomicU64 = AtomicU64::new(0);


/// An extension trait for `SecureRng`
trait SecureRngExt {
	/// Generates a random `len`-sized vector
	fn random_vec(&mut self, len: usize) -> Result<Vec<u8>, Box<dyn Error + 'static>>;
	/// Computes a random number in `range`
	fn random_range(&mut self, range: Range<u128>) -> Result<u128, Box<dyn Error + 'static>>;
	/// Creates a vec with random sized length within `range` filled with random data
	fn random_len_vec(&mut self, range: Range<usize>) -> Result<Vec<u8>, Box<dyn Error + 'static>>;
}
impl SecureRngExt for OsRandom {
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


/// A `ChachaPolyIetf` test vector
struct ChachaPolyIetfTV {
	key: chacha20poly1305_ietf::Key,
	nonce: chacha20poly1305_ietf::Nonce,
	plaintext: Vec<u8>,
	ad: Vec<u8>
}
impl ChachaPolyIetfTV {
	const PLAINTEXT_R: Range<usize> = 0..264;
	const AD_R: Range<usize> = 0..264;
	
	/// Creates a random test vector
	pub fn random() -> Self {
		Self {
			key: chacha20poly1305_ietf::gen_key(),
			nonce: chacha20poly1305_ietf::gen_nonce(),
			plaintext: OsRandom.random_len_vec(Self::PLAINTEXT_R).unwrap(),
			ad: OsRandom.random_len_vec(Self::AD_R).unwrap()
		}
	}
	
	/// Tests the test vector
	pub fn test(self) {
		// Seal the data using `crypto_api_chachapoly`
		let mut ct_ours = vec![0u8; self.plaintext.len() + 16];
		ChachaPolyIetf.seal_to(
			&mut ct_ours, &self.plaintext, &self.ad,
			self.key.as_ref(), self.nonce.as_ref()
		).unwrap();
		
		// Seal the data using `sodiumoxide`
		let ct_sodium = chacha20poly1305_ietf::seal(
			&self.plaintext,
			if self.ad.len() > 0 { Some(&self.ad) } else { None },
			&self.nonce, &self.key
		);
		
		// Compare the data
		if ct_ours != ct_sodium {
			eprintln!("ChachaPoly Mismatch!. Inputs:");
			eprintln!("Key: {:?}", self.key.as_ref());
			eprintln!("Nonce: {:?}", self.nonce.as_ref());
			eprintln!("Plaintext: {:?}", self.plaintext);
			eprintln!("Additional data: {:?}", self.ad);
			eprintln!("Outputs:");
			eprintln!("Ours: {:?}", ct_ours);
			eprintln!("Libsodium: {:?}", ct_sodium);
			panic!("... aborting. Please save and report this error!");
		}
		COUNTER.fetch_add(1, Relaxed);
	}
}


/// A `XChachaPoly` test vector
struct XChachaPolyTV {
	key: xchacha20poly1305_ietf::Key,
	nonce: xchacha20poly1305_ietf::Nonce,
	plaintext: Vec<u8>,
	ad: Vec<u8>
}
impl XChachaPolyTV {
	const PLAINTEXT_R: Range<usize> = 0..264;
	const AD_R: Range<usize> = 0..264;
	
	/// Creates a random test vector
	pub fn random() -> Self {
		Self {
			key: xchacha20poly1305_ietf::gen_key(),
			nonce: xchacha20poly1305_ietf::gen_nonce(),
			plaintext: OsRandom.random_len_vec(Self::PLAINTEXT_R).unwrap(),
			ad: OsRandom.random_len_vec(Self::AD_R).unwrap()
		}
	}
	
	/// Tests the test vector
	pub fn test(self) {
		// Seal the data using `crypto_api_chachapoly`
		let mut ct_ours = vec![0u8; self.plaintext.len() + 16];
		XChachaPoly.seal_to(
			&mut ct_ours, &self.plaintext, &self.ad,
			self.key.as_ref(), self.nonce.as_ref()
		).unwrap();
		
		// Seal the data using `sodiumoxide`
		let ct_sodium = xchacha20poly1305_ietf::seal(
			&self.plaintext,
			if self.ad.len() > 0 { Some(&self.ad) } else { None },
			&self.nonce, &self.key
		);
		
		// Compare the data
		if ct_ours != ct_sodium {
			eprintln!("XChachaPoly Mismatch!. Inputs:");
			eprintln!("Key: {:?}", self.key.as_ref());
			eprintln!("Nonce: {:?}", self.nonce.as_ref());
			eprintln!("Plaintext: {:?}", self.plaintext);
			eprintln!("Additional data: {:?}", self.ad);
			eprintln!("Outputs:");
			eprintln!("Ours: {:?}", ct_ours);
			eprintln!("Libsodium: {:?}", ct_sodium);
			panic!("... aborting. Please save and report this error!");
		}
		COUNTER.fetch_add(1, Relaxed);
	}
}


/// Fuzz it!
fn main() {
	for _ in 0..num_cpus::get() {
		thread::spawn(|| loop {
			ChachaPolyIetfTV::random().test();
			XChachaPolyTV::random().test()
		});
	}
	loop {
		thread::sleep(Duration::from_secs(5));
		println!("Performed {} iterations...", COUNTER.load(Relaxed));
	}
}