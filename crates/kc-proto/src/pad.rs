//! The plaintext format inside every encryption: `pad(postcard(value))`.
//!
//! `pad(x) = u32be(len x) || x || zeros`, up to the next multiple of
//! [`PAD_BUCKET_BYTES`]. Unpadding rejects a total that isn't a multiple of
//! the bucket, a length that doesn't fit, and non-zero padding. The postcard
//! value must use exactly `len` bytes.

use kc_wire::limits::PAD_BUCKET_BYTES;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PadError {
    #[error("value could not be encoded")]
    Encode,
    #[error("padded length is invalid")]
    BadLength,
    #[error("padding is not zero")]
    BadPadding,
    #[error("value could not be decoded")]
    Decode,
}

/// Length of `pad(x)` for an `x` of `content_len` bytes.
pub(crate) fn padded_len(content_len: usize) -> usize {
    (4 + content_len).div_ceil(PAD_BUCKET_BYTES) * PAD_BUCKET_BYTES
}

/// Returns `head || pad(postcard(value))` in one wiped buffer that has room
/// for `tail_room` more bytes, so appending a tag never reallocates.
pub(crate) fn encode<T: Serialize + ?Sized>(
    value: &T,
    head: &[u8],
    tail_room: usize,
) -> Result<Zeroizing<Vec<u8>>, PadError> {
    let n = postcard::serialize_with_flavor(value, postcard::ser_flavors::Size::default())
        .map_err(|_| PadError::Encode)?;
    let len = u32::try_from(n).map_err(|_| PadError::Encode)?;
    let total = padded_len(n);
    let mut buf = Zeroizing::new(Vec::with_capacity(head.len() + total + tail_room));
    buf.extend_from_slice(head);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.resize(head.len() + total, 0);
    let start = head.len() + 4;
    let written =
        postcard::to_slice(value, &mut buf[start..start + n]).map_err(|_| PadError::Encode)?;
    if written.len() != n {
        return Err(PadError::Encode);
    }
    Ok(buf)
}

/// Removes the padding and decodes the value.
pub(crate) fn decode<T: DeserializeOwned>(padded: &[u8]) -> Result<T, PadError> {
    if padded.is_empty() || !padded.len().is_multiple_of(PAD_BUCKET_BYTES) {
        return Err(PadError::BadLength);
    }
    let (len, rest) = padded.split_at(4);
    let len = u32::from_be_bytes(len.try_into().map_err(|_| PadError::BadLength)?) as usize;
    if len > rest.len() {
        return Err(PadError::BadLength);
    }
    let (content, padding) = rest.split_at(len);
    if padding.iter().any(|b| *b != 0) {
        return Err(PadError::BadPadding);
    }
    let (value, trailing) =
        postcard::take_from_bytes::<T>(content).map_err(|_| PadError::Decode)?;
    if !trailing.is_empty() {
        return Err(PadError::Decode);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_are_bucketed() {
        assert_eq!(padded_len(0), 4096);
        assert_eq!(padded_len(4092), 4096);
        assert_eq!(padded_len(4093), 8192);
        assert_eq!(padded_len(10_000), 12_288);
    }

    #[test]
    fn round_trip_with_head_and_tail_room() {
        let value = (1u8, String::from("hello"), vec![7u16; 300]);
        let buf = encode(&value, b"HEAD", 16).unwrap();
        assert_eq!(&buf[..4], b"HEAD");
        assert_eq!((buf.len() - 4) % 4096, 0);
        assert!(buf.capacity() >= buf.len() + 16);
        let back: (u8, String, Vec<u16>) = decode(&buf[4..]).unwrap();
        assert_eq!(back, value);
    }

    #[test]
    fn rejects_bad_padding() {
        let good = encode(&(1u8, 2u8), &[], 0).unwrap();
        assert_eq!(decode::<(u8, u8)>(&good).unwrap(), (1, 2));

        assert_eq!(decode::<(u8, u8)>(&[]), Err(PadError::BadLength));
        assert_eq!(decode::<(u8, u8)>(&good[..4095]), Err(PadError::BadLength));
        let mut longer = good.to_vec();
        longer.push(0);
        assert_eq!(decode::<(u8, u8)>(&longer), Err(PadError::BadLength));

        let mut too_long = good.to_vec();
        too_long[..4].copy_from_slice(&4093u32.to_be_bytes());
        assert_eq!(decode::<(u8, u8)>(&too_long), Err(PadError::BadLength));

        let mut dirty = good.to_vec();
        dirty[4095] = 1;
        assert_eq!(decode::<(u8, u8)>(&dirty), Err(PadError::BadPadding));

        // A length that covers more than the value: the extra byte is trailing data.
        let mut trailing = good.to_vec();
        trailing[..4].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(decode::<(u8, u8)>(&trailing), Err(PadError::Decode));

        // A length that cuts the value short.
        let mut short = good.to_vec();
        short[..4].copy_from_slice(&1u32.to_be_bytes());
        short[5] = 0;
        assert_eq!(decode::<(u8, u8)>(&short), Err(PadError::Decode));
    }
}
