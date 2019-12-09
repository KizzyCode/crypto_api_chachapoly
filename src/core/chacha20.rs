/// ChaCha20 constants
const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];


/// Performs the ChaCha20 rounds over `state`
fn chacha20_rounds(state: &mut[u32]) {
	for _ in 0..10 {
		/// A ChaCha20 quarterround
		macro_rules! quarterround {
			($a:expr, $b:expr, $c:expr, $d:expr) => ({
				state[$a] = add!(state[$a], state[$b]);
				state[$d] = xor!(state[$d], state[$a]);
				state[$d] = or!(shl!(state[$d], 16), shr!(state[$d], 16));
				state[$c] = add!(state[$c], state[$d]);
				state[$b] = xor!(state[$b], state[$c]);
				state[$b] = or!(shl!(state[$b], 12), shr!(state[$b], 20));
				state[$a] = add!(state[$a], state[$b]);
				state[$d] = xor!(state[$d], state[$a]);
				state[$d] = or!(shl!(state[$d],  8), shr!(state[$d], 24));
				state[$c] = add!(state[$c], state[$d]);
				state[$b] = xor!(state[$b], state[$c]);
				state[$b] = or!(shl!(state[$b],  7), shr!(state[$b], 25));
			});
		}
		
		// Perform 8 quarterrounds (2 rounds)
		quarterround!( 0,  4,  8, 12);
		quarterround!( 1,  5,  9, 13);
		quarterround!( 2,  6, 10, 14);
		quarterround!( 3,  7, 11, 15);
		quarterround!( 0,  5, 10, 15);
		quarterround!( 1,  6, 11, 12);
		quarterround!( 2,  7,  8, 13);
		quarterround!( 3,  4,  9, 14);
	}
}


/// A HChaCha20 implementation
pub fn hchacha20_hash(key: &[u8], nonce: &[u8], buf: &mut[u8]) {
	// Read key and nonce
	let mut key_words = vec![0; 8];
	(0..8).for_each(|i| key_words[i] = read32_le!(&key[i * 4..]));
	
	let mut input_words = vec![0; 4];
	(0..4).for_each(|i| input_words[i] = read32_le!(&nonce[i * 4..]));
	
	// Initialize and compute block
	let mut state = vec![0u32; 16];
	state[ 0.. 4].copy_from_slice(&CONSTANTS);
	state[ 4..12].copy_from_slice(&key_words);
	state[12..16].copy_from_slice(&input_words);
	chacha20_rounds(&mut state);
	
	// Write output
	let (buf0, buf1) = buf.split_at_mut(16);
	( 0.. 4).for_each(|i| write32_le!(state[i] => &mut buf0[ i       * 4..]));
	(12..16).for_each(|i| write32_le!(state[i] => &mut buf1[(i - 12) * 4..]));
}


/// Computes the `n`th ChaCha20-IETF block with `key` and `nonce` into `buf`
pub fn chacha20_ietf_block(key: &[u8], nonce: &[u8], n: u32, buf: &mut[u8]) {
	// Read key and nonce
	let mut key_words = vec![0; 8];
	(0..8).for_each(|i| key_words[i] = read32_le!(&key[i * 4..]));
	
	let mut nonce_words = vec![0; 3];
	(0..3).for_each(|i| nonce_words[i] = read32_le!(&nonce[i * 4..]));
	
	// Initialize and compute block
	let mut state = vec![0u32; 16];
	state[ 0.. 4].copy_from_slice(&CONSTANTS);
	state[ 4..12].copy_from_slice(&key_words);
	state[12] = n;
	state[13..16].copy_from_slice(&nonce_words);
	chacha20_rounds(&mut state);
	
	// Finalize block
	( 0.. 4).for_each(|i| write32_le!(add!(state[i],   CONSTANTS[i     ]) => &mut buf[i * 4..]));
	( 4..12).for_each(|i| write32_le!(add!(state[i],   key_words[i -  4]) => &mut buf[i * 4..]));
	write32_le!(add!(state[12], n) => &mut buf[48..]);
	(13..16).for_each(|i| write32_le!(add!(state[i], nonce_words[i - 13]) => &mut buf[i * 4..]));
}


/// Computes the `n`th ChaCha20 block with `key` and `nonce` into `buf`
pub fn chacha20_block(key: &[u8], nonce: &[u8], n: u64, buf: &mut[u8]) {
	// Read key and nonce
	let mut key_words = vec![0; 8];
	(0..8).for_each(|i| key_words[i] = read32_le!(&key[i * 4..]));
	
	let mut nonce_words = vec![0; 2];
	(0..2).for_each(|i| nonce_words[i] = read32_le!(&nonce[i * 4..]));
	
	// Initialize and compute block
	let mut state = vec![0u32; 16];
	state[ 0.. 4].copy_from_slice(&CONSTANTS);
	state[ 4..12].copy_from_slice(&key_words);
	split64_le!(n => &mut state[12..]);
	state[14..16].copy_from_slice(&nonce_words);
	chacha20_rounds(&mut state);
	
	// Finalize block
	( 0.. 4).for_each(|i| write32_le!(add!(state[i],   CONSTANTS[i     ]) => &mut buf[i * 4..]));
	( 4..12).for_each(|i| write32_le!(add!(state[i],   key_words[i -  4]) => &mut buf[i * 4..]));
	write64_le!(add!(combine32_le!(&state[12..]), n) => &mut buf[48..]);
	(14..16).for_each(|i| write32_le!(add!(state[i], nonce_words[i - 14]) => &mut buf[i * 4..]));
}