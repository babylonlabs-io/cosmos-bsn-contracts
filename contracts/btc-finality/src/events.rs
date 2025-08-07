use cosmwasm_std::Event;

/// FinalityProviderStatus represents the status of a finality provider,
/// following the same enum values as defined in babylon/proto/babylon/btcstaking/v1/events.proto
/// ref https://github.com/babylonlabs-io/babylon/blob/e01948b4919f04bae51e8910a93769132382ed13/proto/babylon/btcstaking/v1/events.proto#L129
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Some variants are not used yet but defined for completeness
pub enum FinalityProviderStatus {
    /// FINALITY_PROVIDER_STATUS_INACTIVE defines a finality provider that does not have sufficient
    /// delegations or does not have timestamped public randomness.
    Inactive,
    /// FINALITY_PROVIDER_STATUS_ACTIVE defines a finality provider that have sufficient delegations
    /// and have timestamped public randomness.
    Active,
    /// FINALITY_PROVIDER_STATUS_JAILED defines a finality provider that is jailed due to downtime
    Jailed,
    /// FINALITY_PROVIDER_STATUS_SLASHED defines a finality provider that is slashed due to double-sign
    Slashed,
}

impl FinalityProviderStatus {
    /// Returns the string representation as defined in the proto enum
    pub fn as_str(&self) -> &'static str {
        match self {
            FinalityProviderStatus::Inactive => "FINALITY_PROVIDER_STATUS_INACTIVE",
            FinalityProviderStatus::Active => "FINALITY_PROVIDER_STATUS_ACTIVE",
            FinalityProviderStatus::Jailed => "FINALITY_PROVIDER_STATUS_JAILED",
            FinalityProviderStatus::Slashed => "FINALITY_PROVIDER_STATUS_SLASHED",
        }
    }
}

/// Creates a new finality provider status change event, following the same pattern
/// as NewFinalityProviderStatusChangeEvent in babylon/x/btcstaking/types/events.go
pub fn new_finality_provider_status_change_event(
    btc_pk: &str,
    status: FinalityProviderStatus,
) -> Event {
    Event::new("finality_provider_status_change")
        .add_attribute("btc_pk", btc_pk)
        .add_attribute("new_state", status.as_str())
}
