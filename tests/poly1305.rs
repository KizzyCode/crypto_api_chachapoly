use crypto_api_chachapoly::{ ChachaPolyError, Poly1305 };
include!("read_test_vectors.rs");


#[derive(Debug)]
pub struct TestVector {
	line: usize,
	key___: Vec<u8>,
	input_: Vec<u8>,
	output: Vec<u8>
}
impl TestVector {
	pub fn test(&self) {
		// Create the MAC instance
		let mac = Poly1305::mac();
		
		// Compute the tag
		let mut buf = [0u8; 32];
		let out_len = mac.auth(&mut buf, &self.input_, &self.key___).unwrap();
		assert_eq!(self.output, &buf[..out_len], "@{} failed", self.line);
	}
}
#[test]
fn test() {
	// Read test vectors
	let vectors: Vec<TestVector> = read_test_vectors!(
		"poly1305.txt"
			=> TestVector{ line, key___, input_, output }
	);
	
	// Test all vectors
	for vector in vectors { vector.test() }
}


#[derive(Debug)]
pub struct ApiTestVector {
	line: usize,
	key_len___: usize,
	input_len_: usize,
	output_len: usize,
	error_desc: &'static str
}
impl ApiTestVector {
	pub fn test(&self) {
		// Create the MAC instance
		let mac = Poly1305::mac();
		
		// Create fake inputs
		let key = vec![0; self.key_len___];
		let input = vec![0; self.input_len_];
		let mut output = vec![0; self.output_len];
		
		// Compute the tag
		let err = mac.auth(&mut output, &input, &key).unwrap_err();
		match err.downcast_ref::<ChachaPolyError>() {
			Some(ChachaPolyError::ApiMisuse(desc)) => assert_eq!(
				*desc, self.error_desc,
				"Invalid API-error description @{}", self.line
			),
			_ => panic!("Invalid error returned @{}", self.line)
		}
	}
}
#[test]
fn test_api() {
	// Read test vectors
	let vectors: Vec<ApiTestVector> = read_test_vectors!(
		"poly1305_api.txt"
			=> ApiTestVector{ line, key_len___, input_len_, output_len, error_desc }
	);
	
	// Test all vectors
	for vector in vectors { vector.test() }
}