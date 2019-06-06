#[cfg(feature = "run_examples")]
	extern crate rand;
#[cfg(feature = "run_examples")]
	extern crate sodiumoxide;

#[cfg(feature = "run_examples")]
mod libsodium_compare {
	extern crate rand;
	extern crate sodiumoxide;
	
	use crypto_api_chachapoly::ChachaPolyIetf;
	use crypto_api::cipher::AeadCipher;
	use rand::Rng;
	use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
	
	pub fn test() {
		let chachapoly = ChachaPolyIetf;
		
		let mut rng = rand::thread_rng();
		let mut test_count = 0u64;
		loop {
			// Create random key and nonce
			let key = chacha20poly1305_ietf::gen_key();
			let nonce = chacha20poly1305_ietf::gen_nonce();
			
			// Create new random plaintext
			let mut plaintext = vec![0u8; rng.gen_range(0, 65)];
			rng.fill(plaintext.as_mut_slice());
			
			// Randomly use additional data
			let ad: &[u8] = match rng.gen_bool(0.5) {
				true => &plaintext,
				false => b""
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
				println!("FAILURE! This library and libsodium don't match. Inputs:");
				println!("Key: {:?}", key.as_ref());
				println!("Nonce: {:?}", nonce.as_ref());
				println!("Plaintext: {:?}", plaintext);
				println!("Additional data: {:?}", ad);
				println!("Outputs:");
				println!("Ours: {:?}", ct_ours);
				println!("Libsodium: {:?}", ct_sodium);
				break;
			}
			
			// Track and print iterations
			test_count += 1;
			let scale = 1_000_000;
			if test_count % scale == 0 {
				println!("Completed {}M tests.", test_count/scale);
			}
		}
	}
}

fn main() {
	#[cfg(feature = "run_examples")]
		libsodium_compare::test();
	#[cfg(not(feature = "run_examples"))]
		panic!("Build with feature `run_examples` to run the examples");
}