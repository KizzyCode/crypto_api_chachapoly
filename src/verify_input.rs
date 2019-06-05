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


/// Verifies that
///  - `$key` has the same size as `CHACHA20_KEY` (32 bytes)
///  - `$nonce` has the same size as `CHACHA20_NONCE` (12 bytes)
///  - `$plaintext` is not larger than the maximum plaintext limit
///  - `$buf` is large enough to hold the encrypted plaintext
macro_rules! vfy_enc {
	($key:expr, $nonce:expr, $plaintext:expr => $buf:expr) => ({
		#[allow(unused_imports)]
		use $crate::verify_input::{ UsizeExt, SliceExt };
		
		let error = match true {
			_ if $key._cv() != CHACHA20_KEY => Err("Invalid key length"),
			_ if $nonce._cv() != CHACHA20_NONCE => Err("Invalid nonce length"),
			_ if $plaintext._cv() > CHACHA20_MAX => Err("Too much data"),
			_ if $plaintext._cv() > $buf._cv() => Err("Buffer is too small"),
			_ => Ok(())
		};
		error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
	})
}
/// Verifies that
///  - `$key` has the same size as `CHACHA20_KEY` (32 bytes)
///  - `nonce` has the same size as `CHACHA20_NONCE` (12 bytes)
///  - `$ciphertext` is not larger than the maximum plaintext limit
///  - `$buf` is large enough to hold the decrypted ciphertext
macro_rules! vfy_dec {
	($key:expr, $nonce:expr, $ciphertext:expr => $buf:expr) => ({
		#[allow(unused_imports)]
		use $crate::verify_input::{ UsizeExt, SliceExt };
		
		let error = match true {
			_ if $key._cv() != CHACHA20_KEY => Err("Invalid key length"),
			_ if $nonce._cv() != CHACHA20_NONCE => Err("Invalid nonce length"),
			_ if $ciphertext._cv() > CHACHA20_MAX => Err("Too much data"),
			_ if $ciphertext._cv() > $buf._cv() => Err("Buffer is too small"),
			_ => Ok(())
		};
		error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
	})
}


/// Verifies that
///  - `$key` has the same size as `POLY1305_KEY` (32 bytes)
///  - `$buf` is large enough to a `POLY1305_TAG` (16 bytes)
macro_rules! vfy_auth {
	($key:expr, => $buf:expr) => ({
		#[allow(unused_imports)]
		use $crate::verify_input::{ UsizeExt, SliceExt };
		
		let error = match true {
			_ if $key._cv() != POLY1305_KEY => Err("Invalid key length"),
			_ if $buf._cv() < POLY1305_TAG => Err("Buffer is too small"),
			_ => Ok(())
		};
		error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
	})
}


/// Verifies that
///  - `$key` has the same size as `CHACHAPOLY_KEY` (32 bytes)
///  - `nonce` has the same size as `CHACHAPOLY_NONCE` (12 bytes)
///  - `$plaintext` is not larger than the maximum plaintext limit
///  - `$buf` is large enough to hold the encrypted plaintext and the authentication tag
macro_rules! vfy_seal {
	($key:expr, $nonce:expr, $plaintext:expr => $buf:expr) => ({
		#[allow(unused_imports)]
		use $crate::verify_input::{ UsizeExt, SliceExt };
		
		let error = match true {
			_ if $key._cv() != CHACHAPOLY_KEY => Err("Invalid key length"),
			_ if $nonce._cv() != CHACHAPOLY_NONCE => Err("Invalid nonce length"),
			_ if $plaintext._cv() > CHACHAPOLY_MAX => Err("Too much data"),
			_ if $buf._cv() < $plaintext._cv() + CHACHAPOLY_TAG => Err("Buffer is too small"),
			_ => Ok(())
		};
		error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
	})
}
/// Verifies that
///  - `$key` has the same size as `CHACHAPOLY_KEY` (32 bytes)
///  - `nonce` has the same size as `CHACHAPOLY_NONCE` (12 bytes)
///  - `$ciphertext` is not larger that the maximum plaintext limit and smaller than an
///    authentication tag
///  - `$buf` is large enough to hold the **encrypted** ciphertext (copy and authenticate and
///    decrypt-in-place workflow)
macro_rules! vfy_open {
	($key:expr, $nonce:expr, $ciphertext:expr => $buf:expr) => ({
		#[allow(unused_imports)]
		use $crate::verify_input::{ UsizeExt, SliceExt };
	
		let error = match true {
			_ if $key._cv() != CHACHAPOLY_KEY => Err("Invalid key length"),
			_ if $nonce._cv() != CHACHAPOLY_NONCE => Err("Invalid nonce length"),
			_ if $ciphertext._cv() > CHACHAPOLY_MAX => Err("Too much data"),
			_ if $ciphertext._cv() < CHACHAPOLY_TAG => Err($crate::ChachaPolyError::InvalidData)?,
			_ if $buf._cv() < $ciphertext._cv() => Err("Buffer is too small"),
			_ => Ok(())
		};
		error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
	})
}