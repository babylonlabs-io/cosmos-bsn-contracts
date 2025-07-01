use ics23::ProofSpec as Ics23ProofSpec;

/// An array of proof specifications.
///
/// This type encapsulates different types of proof specifications, mostly predefined, e.g., for
/// Cosmos-SDK.
#[derive(Clone, Debug, PartialEq)]
pub struct ProofSpecs(Vec<Ics23ProofSpec>);

impl ProofSpecs {
    /// Returns the specification for Cosmos-SDK proofs
    pub fn cosmos() -> Self {
        vec![
            ics23::iavl_spec(),       // Format of proofs-iavl (iavl merkle proofs)
            ics23::tendermint_spec(), // Format of proofs-tendermint (crypto/ merkle SimpleProof)
        ]
        .into()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for ProofSpecs {
    fn default() -> Self {
        Self::cosmos()
    }
}

impl From<Vec<Ics23ProofSpec>> for ProofSpecs {
    fn from(ics23_specs: Vec<Ics23ProofSpec>) -> Self {
        Self(ics23_specs.into_iter().collect())
    }
}

impl From<ProofSpecs> for Vec<Ics23ProofSpec> {
    fn from(specs: ProofSpecs) -> Self {
        specs.0.into_iter().collect()
    }
}
