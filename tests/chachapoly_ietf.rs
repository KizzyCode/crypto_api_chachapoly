use crypto_api_chachapoly::{ ChachaPolyError, ChachaPolyIetf };
include!("read_test_vectors.rs");


#[derive(Debug)]
pub struct TestVector {
	line: usize,
	key___: Vec<u8>,
	nonce_: Vec<u8>,
	ad____: Vec<u8>,
	input_: Vec<u8>,
	output: Vec<u8>
}
impl TestVector {
	pub fn test(&self) {
		match self.ad____.is_empty() {
			true => self.test_cipher(),
			false => self.test_aead_cipher()
		}
	}
	
	fn test_cipher(&self) {
		// Create the cipher instance
		let cipher = ChachaPolyIetf::cipher();
		
		// Encrypt the data
		let mut buf = vec![0; self.output.len()];
		let out_len = cipher
			.encrypt_to(&mut buf, &self.input_, &self.key___, &self.nonce_)
			.unwrap();
		assert_eq!(self.output, &buf[..out_len], "@{} failed", self.line);
		
		// Decrypt the data
		let mut buf = vec![0; self.output.len()];
		let out_len = cipher
			.decrypt_to(&mut buf, &self.output, &self.key___, &self.nonce_)
			.unwrap();
		assert_eq!(self.input_, &buf[..out_len], "@{} failed", self.line);
	}
	fn test_aead_cipher(&self) {
		// Create the cipher instance
		let aead_cipher = ChachaPolyIetf::aead_cipher();
		
		// Seal the data
		let mut buf = vec![0; self.output.len()];
		let out_len = aead_cipher.seal_to(
			&mut buf, &self.input_, &self.ad____,
			&self.key___, &self.nonce_
		).unwrap();
		assert_eq!(self.output, &buf[..out_len], "@{} failed", self.line);
		
		// Open the data
		let mut buf = vec![0; self.output.len()];
		let out_len = aead_cipher.open_to(
			&mut buf, &self.output, &self.ad____,
			&self.key___, &self.nonce_
		).unwrap();
		assert_eq!(self.input_, &buf[..out_len], "@{} failed", self.line);
	}
}
#[test]
fn test() {
	// Read test vectors
	let vectors: Vec<TestVector> = read_test_vectors!(
		"chachapoly_ietf.txt"
			=> TestVector{ line, key___, nonce_, ad____, input_, output }
	);
	
	// Test all vectors
	for vector in vectors { vector.test() }
}


#[derive(Debug)]
pub struct ErrTestVector {
	line: usize,
	key__: Vec<u8>,
	nonce: Vec<u8>,
	ad___: Vec<u8>,
	input: Vec<u8>
}
impl ErrTestVector {
	pub fn test(&self) {
		match self.ad___.is_empty() {
			true => self.test_cipher(),
			false => self.test_aead_cipher()
		}
	}
	
	fn test_cipher(&self) {
		// Create the cipher instance
		let cipher = ChachaPolyIetf::cipher();
		
		// Decrypt the data
		let mut buf = vec![0; self.input.len()];
		let err = cipher
			.decrypt_to(&mut buf, &self.input, &self.key__, &self.nonce)
			.unwrap_err();
		match err.downcast_ref::<ChachaPolyError>() {
			Some(ChachaPolyError::InvalidData) => (),
			_ => panic!("Invalid error returned @{}", self.line)
		}
	}
	fn test_aead_cipher(&self) {
		// Create the cipher instance
		let aead_cipher = ChachaPolyIetf::aead_cipher();
		
		// Open the data
		let mut buf = vec![0; self.input.len()];
		let err = aead_cipher.open_to(
			&mut buf, &self.input, &self.ad___,
			&self.key__, &self.nonce
		).unwrap_err();
		match err.downcast_ref::<ChachaPolyError>() {
			Some(ChachaPolyError::InvalidData) => (),
			_ => panic!("Invalid error returned @{}", self.line)
		}
	}
}
#[test]
fn test_err() {
	// Read test vectors
	let vectors: Vec<ErrTestVector> = read_test_vectors!(
		"chachapoly_ietf_err.txt"
			=> ErrTestVector{ line, key__, nonce, ad___, input }
	);
	
	// Test all vectors
	for vector in vectors { vector.test() }
}


#[derive(Debug)]
pub struct ApiTestVector {
	line: usize,
	key_len___: usize,
	nonce_len_: usize,
	ad_len____: usize,
	input_len_: usize,
	output_len: usize,
	error_desc: &'static str
}
impl ApiTestVector {
	pub fn test(&self) {
		match self.ad_len____ {
			0 => self.test_cipher(),
			_ => self.test_aead_cipher()
		}
	}
	
	fn test_cipher(&self) {
		// Create the cipher instance
		let cipher = ChachaPolyIetf::cipher();
		
		// Generate fake inputs
		let key = vec![0; self.key_len___];
		let nonce = vec![0; self.nonce_len_];
		let input = vec![0; self.input_len_];
		let mut buf = vec![0; self.output_len];
		
		// Helper to check the error
		macro_rules! test_err {
			($fn:expr => $call:expr) => ({
				let result = $call
					.expect_err(&format!("`{}`: Unexpected success @{}", $fn, self.line));
				
				match result.downcast_ref::<ChachaPolyError>() {
					Some(ChachaPolyError::ApiMisuse(desc)) => assert_eq!(
						*desc, self.error_desc,
						"`{}`: Invalid API-error description @{}", $fn, self.line
					),
					_ => panic!("`{}`: Invalid error returned @{}", $fn, self.line)
				}
			});
		}
		
		// Test `encrypt` and `encrypt_to`
		test_err!("encrypt" => cipher.encrypt(&mut buf, input.len(), &key, &nonce));
		test_err!("encrypt_to" => cipher.encrypt_to(&mut buf, &input, &key, &nonce));
		
		// Test `decrypt` and `decrypt_to`
		test_err!("decrypt" => cipher.decrypt(&mut buf, input.len(), &key, &nonce));
		test_err!("decrypt_to" => cipher.decrypt_to(&mut buf, &input, &key, &nonce));
	}
	fn test_aead_cipher(&self) {
		// Create the cipher instance
		let aead_cipher = ChachaPolyIetf::aead_cipher();
		
		// Generate fake inputs
		let key = vec![0; self.key_len___];
		let nonce = vec![0; self.nonce_len_];
		let ad = vec![0; self.ad_len____];
		let input = vec![0; self.input_len_];
		let mut buf = vec![0; self.output_len];
		
		// Helper to check the error
		macro_rules! test_err {
			($fn:expr => $call:expr) => ({
				let result = $call
					.expect_err(&format!("`{}`: Unexpected success @{}", $fn, self.line));
				
				match result.downcast_ref::<ChachaPolyError>() {
					Some(ChachaPolyError::ApiMisuse(desc)) => assert_eq!(
						*desc, self.error_desc,
						"`{}`: Invalid API-error description @{}", $fn, self.line
					),
					_ => panic!("`{}`: Invalid error returned @{}", $fn, self.line)
				}
			});
		}
		
		// Test `seal` and `seal_to`
		test_err!("seal" => aead_cipher.seal(&mut buf, input.len(), &ad, &key, &nonce));
		test_err!("seal_to" => aead_cipher.seal_to(&mut buf, &input, &ad, &key, &nonce));
		
		// Test `open` and `open_to`
		test_err!("open" => aead_cipher.open(&mut buf, input.len(), &ad, &key, &nonce));
		test_err!("open_to" => aead_cipher.open_to(&mut buf, &input, &ad, &key, &nonce));
	}
}
#[test]
fn test_api() {
	// Read test vectors
	let vectors: Vec<ApiTestVector> = read_test_vectors!(
		"chachapoly_ietf_api.txt" => ApiTestVector {
			line, key_len___, nonce_len_,
			ad_len____, input_len_, output_len, error_desc
		}
	);
	
	// Test all vectors
	for vector in vectors { vector.test() }
}