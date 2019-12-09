/// A `usize` extension to use `usize`s as constrainable values
pub trait UsizeExt {
	/// Get the constrainable value
	fn _cv(&self) -> usize;
}
impl UsizeExt for usize {
	fn _cv(&self) -> usize {
		*self
	}
}
/// A slice extension to use slice as constrainable values
pub trait SliceExt {
	/// Get the constrainable value
	fn _cv(&self) -> usize;
}
impl<T: AsRef<[u8]>> SliceExt for T {
	fn _cv(&self) -> usize {
		self.as_ref().len()
	}
}


/// Verifies that
///  - `$buf` is can hold *exactly* `$size` bytes
macro_rules! vfy_keygen {
	($size:expr => $buf:expr) => ({
		#[allow(unused_imports)]
		use $crate::verify_input::{ UsizeExt, SliceExt };
		
		let error = match true {
			_ if $buf._cv() != $size => Err("Invalid buffer size"),
			_ => Ok(())
		};
		error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
	});
}


/// Verifies the encryption parameters
macro_rules! vfy_enc {
	($key:expr => [$key_size:expr], $nonce:expr => [$nonce_size:expr],
		$plaintext:expr => [$buf:expr, $plaintext_limit:expr]) =>
	({
		#[allow(unused_imports)]
		use $crate::verify_input::{ UsizeExt, SliceExt };
		
		let error = match true {
			_ if $key._cv() != $key_size => Err("Invalid key length"),
			_ if $nonce._cv() != $nonce_size => Err("Invalid nonce length"),
			_ if $plaintext._cv() > $plaintext_limit => Err("Too much data"),
			_ if $plaintext._cv() > $buf._cv() => Err("Buffer is too small"),
			_ => Ok(())
		};
		error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
	})
	
}
/// Verifies the decryption parameters
macro_rules! vfy_dec {
	($key:expr => [$key_size:expr], $nonce:expr => [$nonce_size:expr],
		$ciphertext:expr => [$buf:expr, $ciphertext_limit:expr]) =>
	({
		#[allow(unused_imports)]
		use $crate::verify_input::{ UsizeExt, SliceExt };
		
		let error = match true {
			_ if $key._cv() != $key_size => Err("Invalid key length"),
			_ if $nonce._cv() != $nonce_size => Err("Invalid nonce length"),
			_ if $ciphertext._cv() > $ciphertext_limit => Err("Too much data"),
			_ if $ciphertext._cv() > $buf._cv() => Err("Buffer is too small"),
			_ => Ok(())
		};
		error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
	})
}


/// Verifies the authentication parameters
macro_rules! vfy_auth {
	($key:expr => [$key_size:expr], => [$buf:expr, $tag_size:expr]) => ({
		#[allow(unused_imports)]
		use $crate::verify_input::{ UsizeExt, SliceExt };
		
		let error = match true {
			_ if $key._cv() != $key_size => Err("Invalid key length"),
			_ if $buf._cv() < $tag_size => Err("Buffer is too small"),
			_ => Ok(())
		};
		error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
	})
}


/// Verifies the sealing parameters
macro_rules! vfy_seal {
	($key:expr => [$key_size:expr], $nonce:expr => [$nonce_const:expr],
		$plaintext:expr => [$buf:expr, $plaintext_limit:expr]) =>
	({
		#[allow(unused_imports)]
		use $crate::verify_input::{ UsizeExt, SliceExt };
		
		let error = match true {
			_ if $key._cv() != $key_size => Err("Invalid key length"),
			_ if $nonce._cv() != $nonce_const => Err("Invalid nonce length"),
			_ if $plaintext._cv() > $plaintext_limit => Err("Too much data"),
			_ if $buf._cv() < $plaintext._cv() + CHACHAPOLY_TAG => Err("Buffer is too small"),
			_ => Ok(())
		};
		error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
	})
}
/// Verifies the parameters for opening in place
macro_rules! vfy_open {
	($key:expr => [$key_size:expr], $nonce:expr => [$nonce_size:expr],
		$ciphertext:expr => [$buf:expr, $tag_size:expr, $ciphertext_limit:expr]) =>
	({
		#[allow(unused_imports)]
		use $crate::verify_input::{ UsizeExt, SliceExt };
	
		let error = match true {
			_ if $key._cv() != $key_size => Err("Invalid key length"),
			_ if $nonce._cv() != $nonce_size => Err("Invalid nonce length"),
			_ if $ciphertext._cv() > $ciphertext_limit => Err("Too much data"),
			_ if $ciphertext._cv() < $tag_size => Err($crate::ChachaPolyError::InvalidData)?,
			_ if $buf._cv() + $tag_size < $ciphertext._cv() => Err("Buffer is too small"),
			_ => Ok(())
		};
		error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
	})
}