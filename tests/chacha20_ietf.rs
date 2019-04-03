use crypto_api_chachapoly::{ ChachaPolyError, ChaCha20Ietf };
include!("read_test_vectors.rs");


#[derive(Debug)]
pub struct TestVector {
	line: usize,
	key___: Vec<u8>,
	nonce_: Vec<u8>,
	input_: Vec<u8>,
	output: Vec<u8>
}
impl TestVector {
	pub fn test(&self) {
		// Create the cipher instance
		let cipher = ChaCha20Ietf::cipher();
		
		// Encrypt the data
		let mut buf = vec![0; self.output.len()];
		let out_len = cipher
			.encrypt_to(&mut buf, &self.input_, &self.key___, &self.nonce_)
			.unwrap();
		assert_eq!(self.output, &buf[..out_len], "@{} failed", self.line);
		
		// Decrypt the data
		let mut buf = vec![0; self.input_.len()];
		let out_len = cipher
			.decrypt_to(&mut buf, &self.output, &self.key___, &self.nonce_)
			.unwrap();
		assert_eq!(self.input_, &buf[..out_len], "@{} failed", self.line);
	}
}
#[test]
fn test() {
	// Read test vectors
	let vectors: Vec<TestVector> = read_test_vectors!(
		"chacha20_ietf.txt"
			=> TestVector{ line, key___, nonce_, input_, output }
	);
	
	// Test all vectors
	for vector in vectors { vector.test() }
}


#[derive(Debug)]
pub struct ApiTestVector {
	line: usize,
	key_len___: usize,
	nonce_len_: usize,
	input_len_: usize,
	output_len: usize,
	error_desc: &'static str
}
impl ApiTestVector {
	pub fn test(&self) {
		// Create the cipher instance
		let cipher = ChaCha20Ietf::cipher();
	
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
}
#[test]
fn test_api() {
	// Read test vectors
	let vectors: Vec<ApiTestVector> = read_test_vectors!(
		"chacha20_ietf_api.txt"
			=> ApiTestVector{ line, key_len___, nonce_len_, input_len_, output_len, error_desc }
	);
	
	// Test all vectors
	for vector in vectors { vector.test() }
}