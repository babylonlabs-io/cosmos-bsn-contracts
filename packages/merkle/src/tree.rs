use crate::error::MerkleError;

/// Returns the largest power of 2 less than length.
pub(crate) fn get_split_point(length: u64) -> Result<u64, MerkleError> {
    if length < 1 {
        return Err(MerkleError::generic_err(
            "Trying to split a tree with size < 1",
        ));
    }
    let u_length = length as usize;
    let bit_len = u_length.next_power_of_two().trailing_zeros();
    let k = 1 << bit_len.saturating_sub(1);
    if k == length {
        Ok(k >> 1)
    } else {
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_split_point() {
        let tests = [
            (1, 0),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 4),
            (10, 8),
            (20, 16),
            (100, 64),
            (255, 128),
            (256, 128),
            (257, 256),
        ];
        for (length, want) in tests {
            let got = get_split_point(length).unwrap();
            assert_eq!(got, want, "got {got}, want {want}");
        }
    }
}
