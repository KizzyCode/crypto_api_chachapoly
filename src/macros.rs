/// Addition without overflow-trap
#[doc(hidden)] #[macro_export] macro_rules! add {
	($a:expr, $b:expr) => ({ $a.wrapping_add($b) });
	($a:expr, $b:expr, $c:expr) => ({ $a.wrapping_add($b).wrapping_add($c) });
	($a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => ({
		$a.wrapping_add($b).wrapping_add($c).wrapping_add($d).wrapping_add($e)
	});
}

/// Subtraction without underflow-trap
#[doc(hidden)] #[macro_export] macro_rules! sub {
	($a:expr, $b:expr) => ({ $a.wrapping_sub($b) });
}
/// Multiplies without overflow-trap
#[doc(hidden)] #[macro_export] macro_rules! mul {
	($a:expr, $b:expr) => ({ $a.wrapping_mul($b) });
}

/// Right-shift without overflow-trap
#[doc(hidden)] #[macro_export] macro_rules! shr {
	($a:expr, $b:expr) => ({ $a.wrapping_shr($b) });
}
/// Left-shift without overflow-trap
#[doc(hidden)] #[macro_export] macro_rules! shl {
	($a:expr, $b:expr) => ({ $a.wrapping_shl($b) });
}

/// Negates without trap
#[doc(hidden)] #[macro_export] macro_rules! neg {
	($a:expr) => ({ $a.wrapping_neg() });
}

/// Perform an AND
#[doc(hidden)] #[macro_export] macro_rules! and {
	($a:expr, $b:expr) => ({ $a & $b });
}
/// Perform an OR
#[doc(hidden)] #[macro_export] macro_rules! or {
	($a:expr, $b:expr) => ({ $a | $b });
	($a:expr, $b:expr, $c:expr, $d:expr) => ({ $a | $b | $c | $d });
}
/// Perform a XOR
#[doc(hidden)] #[macro_export] macro_rules! xor {
	($a:expr, $b:expr) => ({ $a ^ $b });
}

/// Checks if `$a > $b` and returns a `u32` (where `1` is `true` and `0` is `false`)
#[doc(hidden)] #[macro_export] macro_rules! gt {
	($a:expr, $b:expr) => ({
		let c = sub!($b, $a);
		shr!(xor!(c, and!(xor!($a, $b), xor!($a, c))), 31)
	});
}
/// Tests if `$a == $b` and returns a `u32` (where `1` is `true` and `0` is `false`)
#[doc(hidden)] #[macro_export] macro_rules! eq {
	($a:expr, $b:expr) => ({
		let q = xor!($a, $b);
		not_bool!(shr!(or!(q, neg!(q)), 31))
	});
}
/// Performs a not for `$a` where `$a` is a `u32`-boolean (where `1` is `true` and `0` is `false`)
#[doc(hidden)] #[macro_export] macro_rules! not_bool {
	($a:expr) => ({ xor!($a, 1) });
}
/// Multiplexer to return `$x` if `$c == 1` or `$y` if `$c == 0`
#[doc(hidden)] #[macro_export] macro_rules! mux_bool {
	($c:expr, $x:expr, $y:expr) => ({ xor!($y, and!(neg!($c), xor!($x, $y))) });
}

/// Little-endian decodes `$data[0..4]` to `$num`
#[doc(hidden)] #[macro_export] macro_rules! read32_le {
	($data:expr) => ({
		or!(
			shl!($data[0] as u32,  0),
			shl!($data[1] as u32,  8),
			shl!($data[2] as u32, 16),
			shl!($data[3] as u32, 24)
		)
	});
}
/// Little-endian encodes `$num` to `$data[0..4]`
#[doc(hidden)] #[macro_export] macro_rules! write32_le {
	($num:expr => $data:expr) => ({
		$data[0] = shr!($num,  0) as u8;
		$data[1] = shr!($num,  8) as u8;
		$data[2] = shr!($num, 16) as u8;
		$data[3] = shr!($num, 24) as u8;
	});
}
/// Little-endian encodes `$num` to `$data[0..8]`
#[doc(hidden)] #[macro_export] macro_rules! write64_le {
	($num:expr => $data:expr) => ({
		write32_le!(shr!($num,  0) => &mut $data[0..]);
		write32_le!(shr!($num, 32) => &mut $data[4..]);
	});
}

/// Compares `$a` and `$b` in constant time if they have the same size
#[macro_export] macro_rules! eq_ct {
	($a:expr, $b:expr) => ({
		match $a.len() == $b.len() {
			true => {
				let mut x = 0;
				for i in 0..$a.len() { x = or!(x, xor!($a[i], $b[i])) }
				x == 0
			},
			false => false
		}
	});
}