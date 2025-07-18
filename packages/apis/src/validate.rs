use crate::btc_staking_api::{
    ActiveBtcDelegation, FinalityProviderDescription, NewFinalityProvider, ProofOfPossessionBtc,
    SlashedBtcDelegation, UnbondedBtcDelegation, HASH_SIZE,
};
use crate::error::StakingApiError;
use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use cosmwasm_std::StdError;

/// Trait for validating the API structs / input.
pub trait Validate {
    fn validate(&self) -> Result<(), StakingApiError>;
}

impl Validate for NewFinalityProvider {
    fn validate(&self) -> Result<(), StakingApiError> {
        self.description
            .as_ref()
            .map(FinalityProviderDescription::validate)
            .transpose()?;

        if self.btc_pk_hex.is_empty() {
            return Err(StakingApiError::EmptyBtcPk);
        }

        let _btc_pk = hex::decode(&self.btc_pk_hex)?;

        // TODO: Validate BTC public key (requires valid BTC PK test data) (#7 extra)
        // PublicKey::from_slice(&btc_pk)
        //     .map_err(|_| StakingApiError::InvalidBtcPk(self.btc_pk_hex.clone()))?;

        match self.pop {
            Some(ref pop) => pop.validate()?,
            None => return Err(StakingApiError::MissingPop),
        }

        // Validate consumer_id
        if self.consumer_id.is_empty() {
            return Err(StakingApiError::EmptyChainId);
        }

        Ok(())
    }
}

impl Validate for FinalityProviderDescription {
    fn validate(&self) -> Result<(), StakingApiError> {
        if self.moniker.is_empty() {
            return Err(StakingApiError::description_err("Moniker cannot be empty"));
        }
        if self.moniker.len() > FinalityProviderDescription::MAX_MONIKER_LENGTH {
            return Err(StakingApiError::description_err(format!(
                "Invalid moniker length; got: {}, max: {}",
                self.moniker.len(),
                FinalityProviderDescription::MAX_MONIKER_LENGTH
            )));
        }

        if self.identity.len() > FinalityProviderDescription::MAX_IDENTITY_LENGTH {
            return Err(StakingApiError::from(StdError::generic_err(format!(
                "Invalid identity length; got: {}, max: {}",
                self.identity.len(),
                FinalityProviderDescription::MAX_IDENTITY_LENGTH
            ))));
        }

        if self.website.len() > FinalityProviderDescription::MAX_WEBSITE_LENGTH {
            return Err(StakingApiError::from(StdError::generic_err(format!(
                "Invalid website length; got: {}, max: {}",
                self.website.len(),
                FinalityProviderDescription::MAX_WEBSITE_LENGTH
            ))));
        }

        if self.security_contact.len() > FinalityProviderDescription::MAX_SECURITY_CONTACT_LENGTH {
            return Err(StakingApiError::from(StdError::generic_err(format!(
                "Invalid security contact length; got: {}, max: {}",
                self.security_contact.len(),
                FinalityProviderDescription::MAX_SECURITY_CONTACT_LENGTH
            ))));
        }

        if self.details.len() > FinalityProviderDescription::MAX_DETAILS_LENGTH {
            return Err(StakingApiError::from(StdError::generic_err(format!(
                "Invalid details length; got: {}, max: {}",
                self.details.len(),
                FinalityProviderDescription::MAX_DETAILS_LENGTH
            ))));
        }

        Ok(())
    }
}

impl Validate for ProofOfPossessionBtc {
    // TODO: Validate proof of possession (#7.0)
    fn validate(&self) -> Result<(), StakingApiError> {
        Ok(())
    }
}

impl Validate for ActiveBtcDelegation {
    fn validate(&self) -> Result<(), StakingApiError> {
        fn check_duplicated_fps(del: &ActiveBtcDelegation) -> Result<(), StakingApiError> {
            let mut fp_btc_pk_set = std::collections::HashSet::new();
            for fp_btc_pk in &del.fp_btc_pk_list {
                if !fp_btc_pk_set.insert(fp_btc_pk) {
                    return Err(StakingApiError::DuplicatedBtcPk(fp_btc_pk.clone()));
                }
            }
            Ok(())
        }

        if self.btc_pk_hex.is_empty() {
            return Err(StakingApiError::EmptyBtcPk);
        }
        if self.staking_tx.is_empty() {
            return Err(StakingApiError::EmptyStakingTx);
        }
        if self.slashing_tx.is_empty() {
            return Err(StakingApiError::EmptySlashingTx);
        }
        let _: Transaction = deserialize(&self.slashing_tx)
            .map_err(|_| StakingApiError::InvalidBtcTx(hex::encode(&self.slashing_tx)))?;

        // TODO: Verify delegator slashing Schnorr signature (#7.2)

        // Ensure the list of finality provider BTC PKs is not empty
        if self.fp_btc_pk_list.is_empty() {
            return Err(StakingApiError::EmptyBtcPkList);
        }
        // Ensure the list of finality provider BTC PKs is not duplicated
        check_duplicated_fps(self)?;

        // TODO: Verifications about undelegation info / on-demand unbonding (#7.2)
        // Check unbonding time is lower than max uint16
        if self.unbonding_time > u16::MAX as u32 {
            return Err(StakingApiError::ErrInvalidUnbondingTime(
                self.unbonding_time,
                u16::MAX as u32,
            ));
        }

        let undelegation_info = &self.undelegation_info;
        // Check that the unbonding tx is there
        if undelegation_info.unbonding_tx.is_empty() {
            return Err(StakingApiError::EmptyUnbondingTx);
        }

        // Check that the unbonding slashing tx is there
        if undelegation_info.slashing_tx.is_empty() {
            return Err(StakingApiError::EmptySlashingTx);
        }

        // Check that the delegator slashing signature is there
        if undelegation_info.delegator_slashing_sig.is_empty() {
            return Err(StakingApiError::EmptySignature);
        }

        Ok(())
    }
}

impl Validate for UnbondedBtcDelegation {
    fn validate(&self) -> Result<(), StakingApiError> {
        if self.staking_tx_hash.len() != HASH_SIZE * 2 {
            return Err(StakingApiError::InvalidStakingTxHash(HASH_SIZE * 2));
        }

        if self.unbonding_tx_sig.is_empty() {
            return Err(StakingApiError::EmptySignature);
        }

        // TODO: Verify delegator unbonding Schnorr signature (#7.3)

        Ok(())
    }
}

impl Validate for SlashedBtcDelegation {
    fn validate(&self) -> Result<(), StakingApiError> {
        if self.staking_tx_hash.len() != HASH_SIZE * 2 {
            return Err(StakingApiError::InvalidStakingTxHash(HASH_SIZE * 2));
        }

        // if self.recovered_fp_btc_sk.is_empty() {
        //     return Err(StakingApiError::EmptyBtcSk);
        // }

        Ok(())
    }
}
