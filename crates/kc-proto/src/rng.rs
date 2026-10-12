//! The operating system's CSPRNG, used for codes, nonces, keys and ids.

/// Fills `buf` from the OS random source.
///
/// # Panics
/// If the OS random source fails. There is no safe fallback for a CSPRNG, and
/// `hpke` makes the same choice.
pub(crate) fn fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("the operating system's random number generator failed");
}

pub(crate) fn array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill(&mut out);
    out
}

/// A uniformly random value in `0..n` (rejection sampling, no modulo bias).
pub(crate) fn below(n: u32) -> u32 {
    assert!(n > 0, "empty range");
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let v = u32::from_le_bytes(array::<4>());
        if v < zone {
            return v % n;
        }
    }
}
