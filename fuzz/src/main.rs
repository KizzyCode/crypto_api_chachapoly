use crypto_api_chachapoly::{ ChachaPolyIetf, XChachaPoly, crypto_api::cipher::AeadCipher };
use sodiumoxide::crypto::{
	stream::salsa20,
	aead::{ chacha20poly1305_ietf, xchacha20poly1305_ietf }
};
use hex::ToHex;
use std::{
	env, thread, ops::Range, str::FromStr, time::Duration,
	sync::atomic::{ AtomicU64, Ordering::Relaxed }
};


/// Set jemalloc as allocator if specified
#[cfg(feature = "jemalloc")]
	#[global_allocator] static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// An atomic test counter
static COUNTER: AtomicU64 = AtomicU64::new(0);


/// A fast but still secure RNG
struct SecureRng {
	seed: salsa20::Key,
	ctr: u64
}
impl SecureRng {
	/// Creates a new RNG
	pub fn new() -> Self {
		Self{ seed: salsa20::gen_key(), ctr: 0 }
	}
	
	/// Fills `buf` with secure random bytes
	pub fn random(&mut self, buf: &mut[u8]) {
		// Create nonce
		let nonce = salsa20::Nonce::from_slice(&self.ctr.to_be_bytes()).unwrap();
		self.ctr += 1;
		
		// Create random bytes
		buf.iter_mut().for_each(|b| *b = 0);
		salsa20::stream_xor_inplace(buf, &nonce, &self.seed);
	}
	/// Creates a `len`-sized vector filled with secure random bytes
	pub fn random_vec(&mut self, len: usize) -> Vec<u8> {
		let mut buf = vec![0; len];
		self.random(&mut buf);
		buf
	}
	/// Computes a secure random number within `range`
	pub fn random_range(&mut self, range: Range<u128>) -> u128 {
		// Compute the bucket size and amount
		let bucket_size = range.end - range.start;
		let bucket_count = u128::max_value() / bucket_size;
		
		// Compute the number
		let mut num = [0; 16];
		loop {
			// Generates a random number
			self.random(&mut num);
			let num = u128::from_ne_bytes(num);
			
			// Check if the number falls into the
			if num < bucket_size * bucket_count {
				return (num % bucket_size) + range.start
			}
		}
	}
	/// Creates a vec with random sized length within `range` filled with secure random data
	pub fn random_len_vec(&mut self, range: Range<usize>) -> Vec<u8> {
		let range = (range.start as u128)..(range.end as u128);
		let len = self.random_range(range) as usize;
		self.random_vec(len)
	}
}


/// A `ChachaPolyIetf` test vector
struct ChachaPolyIetfTV {
	key: Vec<u8>,
	nonce: Vec<u8>,
	plaintext: Vec<u8>,
	ad: Vec<u8>
}
impl ChachaPolyIetfTV {
	/// Creates a random test vector
	pub fn random(limit: usize, rng: &mut SecureRng) -> Self {
		Self {
			key: rng.random_vec(32),
			nonce: rng.random_vec(12),
			plaintext: rng.random_len_vec(0..limit),
			ad: rng.random_len_vec(0..limit)
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
			&chacha20poly1305_ietf::Nonce::from_slice(&self.nonce).unwrap(),
			&chacha20poly1305_ietf::Key::from_slice(&self.key).unwrap()
		);
		
		// Compare the data
		if ct_ours != ct_sodium {
			eprintln!("ChachaPoly Mismatch!. Inputs:");
			eprintln!("Key: {}", self.key.encode_hex::<String>());
			eprintln!("Nonce: {}", self.nonce.encode_hex::<String>());
			eprintln!("Plaintext: {}", self.plaintext.encode_hex::<String>());
			eprintln!("Additional data: {}", self.ad.encode_hex::<String>());
			eprintln!("Outputs:");
			eprintln!("Ours: {}", ct_ours.encode_hex::<String>());
			eprintln!("Libsodium: {}", ct_sodium.encode_hex::<String>());
			panic!("... aborting. Please save and report this error!");
		}
		COUNTER.fetch_add(1, Relaxed);
	}
}


/// A `XChachaPoly` test vector
struct XChachaPolyTV {
	key: Vec<u8>,
	nonce: Vec<u8>,
	plaintext: Vec<u8>,
	ad: Vec<u8>
}
impl XChachaPolyTV {
	/// Creates a random test vector
	pub fn random(limit: usize, rng: &mut SecureRng) -> Self {
		Self {
			key: rng.random_vec(32),
			nonce: rng.random_vec(24),
			plaintext: rng.random_len_vec(0..limit),
			ad: rng.random_len_vec(0..limit)
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
			&xchacha20poly1305_ietf::Nonce::from_slice(&self.nonce).unwrap(),
			&xchacha20poly1305_ietf::Key::from_slice(&self.key).unwrap()
		);
		
		// Compare the data
		if ct_ours != ct_sodium {
			eprintln!("XChachaPoly Mismatch!. Inputs:");
			eprintln!("Key: {}", self.key.encode_hex::<String>());
			eprintln!("Nonce: {}", self.nonce.encode_hex::<String>());
			eprintln!("Plaintext: {}", self.plaintext.encode_hex::<String>());
			eprintln!("Additional data: {}", self.ad.encode_hex::<String>());
			eprintln!("Outputs:");
			eprintln!("Ours: {}", ct_ours.encode_hex::<String>());
			eprintln!("Libsodium: {}", ct_sodium.encode_hex::<String>());
			panic!("... aborting. Please save and report this error!");
		}
		COUNTER.fetch_add(1, Relaxed);
	}
}


/// Fuzz it!
fn main() {
	// Load the amount of threads from the environment
	let threads_str = env::var("THREADS").unwrap_or(num_cpus::get().to_string());
	let threads = usize::from_str(&threads_str).expect("Invalid value of THREADS");
	
	// Load the limit from environment
	let limit_str = env::var("TEST_VECTOR_LIMIT").unwrap_or(264.to_string());
	let limit = usize::from_str(&limit_str).expect("Invalid value of TEST_VECTOR_LIMIT");
	
	// Start fuzzing threads
	for _ in 0 .. threads {
		let mut rng = SecureRng::new();
		thread::spawn(move || loop {
			ChachaPolyIetfTV::random(limit, &mut rng).test();
			XChachaPolyTV::random(limit, &mut rng).test()
		});
	}
	
	// Print progress
	println!("Starting fuzzing [THREADS = {}, TEST_VECTOR_LIMIT = {} bytes]...", threads, limit);
	loop {
		thread::sleep(Duration::from_secs(5));
		println!("Performed {} tests...", COUNTER.load(Relaxed));
	}
}