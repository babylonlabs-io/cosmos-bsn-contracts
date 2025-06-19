use crate::BlockHeader;

// RetargetAdjustmentFactor in https://github.com/btcsuite/btcd/blob/master/chaincfg/params.go
// Its value is always 4
const RETARGET_ADJUSTMENT_FACTOR: u64 = 4;

/// verify_header_pow ensures the header's hash <= the header's target <= pow limit
pub fn verify_header_pow(
    chain_params: &bitcoin::consensus::Params,
    header: &BlockHeader,
) -> Result<(), String> {
    let target = header.target();
    // ensure the target <= pow_limit
    if target > chain_params.max_attainable_target {
        return Err("the header's target should be no larger than pow_limit".to_string());
    }

    // ensure the header's hash <= target
    // NOTE: validate_pow ensures two things
    // - the given required_target is same
    // - the header hash is smaller than required_target
    // The former must be true since we give this header's target
    // Here we are interested in the latter check, in which the code is private
    if header.validate_pow(target).is_err() {
        return Err("the header's hash should be no larger than its target".to_string());
    }

    Ok(())
}

/// verify_next_header_pow checks whether the given btc_header extends the given
/// prev_btc_header, including checking prev hash and PoW.
/// It is identical to BTCLightclient's implementation in
/// https://github.com/babylonlabs-io/babylon/blob/v0.5.0/x/btclightclient/keeper/msg_server.go#L126-L149
pub fn verify_next_header_pow(
    chain_params: &bitcoin::consensus::Params,
    prev_header: &BlockHeader,
    header: &BlockHeader,
) -> Result<(), String> {
    // ensure the header is adjacent to last_btc_header
    if !prev_header.block_hash().eq(&header.prev_blockhash) {
        return Err("the header is not consecutive to the previous header".to_string());
    }

    // ensure the header's hash <= the header's target <= pow limit
    verify_header_pow(chain_params, header)?;

    // if the chain does not allow reduced difficulty after 10min, ensure
    // the new header's target is within the [0.25, 4] range
    if !chain_params.allow_min_difficulty_blocks {
        let retarget_adjustment_factor_u256 =
            cosmwasm_std::Uint256::from(RETARGET_ADJUSTMENT_FACTOR);
        let old_target = cosmwasm_std::Uint256::from_be_bytes(prev_header.target().to_be_bytes());
        let cur_target = cosmwasm_std::Uint256::from_be_bytes(header.target().to_be_bytes());
        let max_cur_target = old_target * retarget_adjustment_factor_u256;
        let min_cur_target = old_target / retarget_adjustment_factor_u256;
        if cur_target > max_cur_target || cur_target < min_cur_target {
            return Err("difficulty not relevant to parent difficulty".to_string());
        }
    }

    Ok(())
}
