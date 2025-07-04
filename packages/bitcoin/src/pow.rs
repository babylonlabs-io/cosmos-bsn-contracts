use crate::error::Error;
use crate::BlockHeader;

/// Ensures the header's hash <= the header's target <= pow limit.
pub fn verify_header_pow(
    chain_params: &bitcoin::consensus::Params,
    header: &BlockHeader,
) -> Result<(), Error> {
    let target = header.target();

    // ensure the target <= pow_limit
    if target > chain_params.max_attainable_target {
        return Err(Error::TargetTooLarge);
    }

    // ensure the header's hash <= target
    // NOTE: validate_pow ensures two things
    // - the given required_target is same
    // - the header hash is smaller than required_target
    // The former must be true since we give this header's target
    // Here we are interested in the latter check, in which the code is private
    header
        .validate_pow(target)
        .map_err(Error::InvalidProofOfWork)?;

    Ok(())
}
