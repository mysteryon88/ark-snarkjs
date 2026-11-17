use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use ark_snarkjs::{AsFp2, CurveTag, export_vk, vk_to_snarkjs};
use std::{fs, path::PathBuf, time::SystemTime};

fn check_public_count<E>()
where
    E: Pairing + CurveTag,
    <E::G1Affine as AffineRepr>::BaseField: PrimeField,
    <E::G2Affine as AffineRepr>::BaseField: AsFp2,
{
    let g1 = E::G1Affine::generator();
    let g2 = E::G2Affine::generator();
    let vk = VerifyingKey::<E> {
        alpha_g1: g1,
        beta_g2: g2,
        gamma_g2: g2,
        delta_g2: g2,
        gamma_abc_g1: vec![g1, g1],
    };
    let json = vk_to_snarkjs(&vk, 1).unwrap();
    assert_eq!(json.nPublic, 1);
    assert_eq!(json.ic.len(), 2);
    for count in [0, 2, usize::MAX] {
        assert!(
            vk_to_snarkjs(&vk, count).is_err(),
            "accepted nPublic={count} for two IC points"
        );
    }

    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".tmp")
        .join(format!(
            "metadata-{}-{}-{}",
            E::NAME,
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("verification_key.json");
    fs::write(&path, b"existing output").unwrap();
    assert!(export_vk(&vk, 0, &path).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"existing output");
    export_vk(&vk, 1, &path).unwrap();
    let written: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(written["nPublic"], 1);
    assert_eq!(written["IC"].as_array().unwrap().len(), 2);
    fs::remove_dir_all(directory).unwrap();

    let mut empty = vk;
    empty.gamma_abc_g1.clear();
    assert!(vk_to_snarkjs(&empty, 0).is_err());
}

#[test]
fn public_count_matches_ic_bn254() {
    check_public_count::<ark_bn254::Bn254>();
}

#[test]
fn public_count_matches_ic_bls12_381() {
    check_public_count::<ark_bls12_381::Bls12_381>();
}
