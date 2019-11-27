mod shared;

use shared::{ JsonValueExt, ResultExt };
use crypto_api_chachapoly::Poly1305;
use json::JsonValue;


/// The test vectors
const TEST_VECTORS: &str = include_str!("poly1305.json");


/// A crypto test vector
#[derive(Debug)]
struct CryptoTestVector {
	name: String,
	key: Vec<u8>,
	data: Vec<u8>,
	mac: Vec<u8>
}
impl CryptoTestVector {
	/// Loads the test vectors
	pub fn load() -> Vec<Self> {
		let json = json::parse(TEST_VECTORS).unwrap();
		let mut vecs = Vec::new();
		for vec in json["crypto"].checked_array_iter() {
			vecs.push(Self {
				name: vec["name"].checked_string(),
				key: vec["key"].checked_bytes(),
				data: vec["data"].checked_bytes(),
				mac: vec["mac"].checked_bytes()
			});
		}
		vecs
	}
	
	/// Tests the MAC computation
	pub fn test_mac(&self) -> &Self {
		// Compute mac
		let mut buf = vec![0; self.mac.len()];
		Poly1305::mac().auth(&mut buf, &self.data, &self.key).unwrap();
		assert_eq!(buf, self.mac, "Test vector: \"{}\"", self.name);
		
		self
	}
}
#[test]
fn test_crypto() {
	for vec in CryptoTestVector::load() {
		vec.test_mac();
	}
}


/// An API test vector
#[derive(Default, Clone, Debug)]
pub struct ApiTestVector {
	name: String,
	key_len: usize,
	data_len: usize,
	buf_len: usize,
	error: String
}
impl ApiTestVector {
	/// Loads the test vectors
	pub fn load() -> Vec<Self> {
		// Load the JSON and create the default struct
		let json = json::parse(TEST_VECTORS).unwrap();
		let mut defaults = Self::default();
		defaults.load_json(&json["api"]["defaults"]);
		
		// Load the test vectors
		let mut vecs = Vec::new();
		for vec in json["api"]["tests"].members() {
			let mut this = defaults.clone();
			this.load_json(vec);
			vecs.push(this);
		}
		vecs
	}
	
	/// Tests the MAC computation
	pub fn test_mac(&self) -> &Self {
		// Prepare fake inputs
		let key = vec![0; self.key_len];
		let data = vec![0; self.data_len];
		let mut buf = vec![0; self.buf_len];
		
		// Compute MAC
		let error = Poly1305::mac().auth(&mut buf, &data, &key)
			.error_or(format!("Test vector: \"{}\"", self.name));
		assert_eq!(error.to_string(), self.error, "Test vector: \"{}\"", self.name);
		
		self
	}
	
	/// Loads all set fields in `j` into `self`
	fn load_json(&mut self, j: &JsonValue) {
		self.name = j["name"].optional_string(&self.name);
		self.key_len = j["key_len"].optional_usize(self.key_len);
		self.data_len = j["data_len"].optional_usize(self.data_len);
		self.buf_len = j["buf_len"].optional_usize(self.buf_len);
		self.error = j["error"].optional_string(&self.error);
	}
}
#[test]
fn test_api() {
	for vec in ApiTestVector::load() {
		vec.test_mac();
	}
}