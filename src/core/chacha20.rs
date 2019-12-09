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
	// Create and init state
	let mut state = vec![0u32; 16];
	( 0.. 4).for_each(|i| state[i] = CONSTANTS[i]);
	( 4..12).for_each(|i| state[i] = read32_le!(  &key[(i -  4) * 4..]));
	(12..16).for_each(|i| state[i] = read32_le!(&nonce[(i - 12) * 4..]));
	
	// Mix the state
	chacha20_rounds(&mut state);
	
	// Write the output
	let (buf0, buf1) = buf.split_at_mut(16);
	( 0.. 4).for_each(|i| write32_le!(state[i] => &mut buf0[ i       * 4..]));
	(12..16).for_each(|i| write32_le!(state[i] => &mut buf1[(i - 12) * 4..]));
}


/// Computes the `n`th ChaCha20-IETF block with `key` and `nonce` into `buf`
pub fn chacha20_ietf_block(key: &[u8], nonce: &[u8], n: u32, buf: &mut[u8]) {
	// Create state buffer
	let mut state = vec![0u32; 32];
	let (init, mixed) = state.split_at_mut(16);
	
	// Init state
	( 0.. 4).for_each(|i| init[i] = CONSTANTS[i]);
	( 4..12).for_each(|i| init[i] = read32_le!(  &key[(i -  4) * 4..]));
	init[12] = n;
	(13..16).for_each(|i| init[i] = read32_le!(&nonce[(i - 13) * 4..]));
	
	// Mix state
	mixed.copy_from_slice(init);
	chacha20_rounds(mixed);
	
	// Add init state to mixed state and write the mixed state to the buffer
	( 0..16).for_each(|i| mixed[i] = add!(mixed[i], init[i]));
	( 0..16).for_each(|i| write32_le!(mixed[i] => &mut buf[i * 4..]));
}


/// Computes the `n`th ChaCha20 block with `key` and `nonce` into `buf`
pub fn chacha20_block(key: &[u8], nonce: &[u8], n: u64, buf: &mut[u8]) {
	// Create state buffer
	let mut state = vec![0u32; 32];
	let (init, mixed) = state.split_at_mut(16);
	
	// Init state
	( 0.. 4).for_each(|i| init[i] = CONSTANTS[i]);
	( 4..12).for_each(|i| init[i] = read32_le!(  &key[(i -  4) * 4..]));
	split64_le!(n => &mut init[12..]);
	(14..16).for_each(|i| init[i] = read32_le!(&nonce[(i - 14) * 4..]));
	
	// Mix state
	mixed.copy_from_slice(init);
	chacha20_rounds(mixed);
	
	// Add init state to mixed state and write the mixed state to the buffer
	( 0..16).for_each(|i| mixed[i] = add!(mixed[i], init[i]));
	( 0..16).for_each(|i| write32_le!(mixed[i] => &mut buf[i * 4..]));
}