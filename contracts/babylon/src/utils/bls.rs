use babylon_proto::babylon::checkpointing::v1::ValidatorWithBlsKeySet;
use blst::min_sig::*;
use std::vec;

fn agg_pk(valset: &ValidatorWithBlsKeySet) -> Result<PublicKey, String> {
    let mut pks: Vec<&[u8]> = vec![];
    for val in valset.val_set.iter() {
        pks.push(&val.bls_pub_key);
    }

    let agg_pk = AggregatePublicKey::aggregate_serialized(&pks, true)
        .map_err(|err| format!("failed to aggregate BLS PKs: {err:?}"))?;
    Ok(agg_pk.to_public_key())
}

pub fn verify_multisig(
    sig_bytes: &[u8],
    valset: &ValidatorWithBlsKeySet,
    msg: &[u8],
) -> Result<(), String> {
    // Domain Separation Tag for signatures on G1 (minimal-signature-size)
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    // decode signature
    let sig = Signature::from_bytes(sig_bytes)
        .map_err(|err| format!("failed to decode signature bytes with code {err:?}"))?;

    // get agg pk from valset
    let agg_pk = agg_pk(valset)?;

    // verify multisig
    let res = sig.verify(true, msg, dst, &[], &agg_pk, true);
    if res == blst::BLST_ERROR::BLST_SUCCESS {
        return Ok(());
    }
    Err(format!(
        "failed to verify BLS multisignature with code {res:?}"
    ))
}
