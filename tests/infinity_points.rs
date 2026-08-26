use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_groth16::{Proof, VerifyingKey};
use ark_snarkjs::{export_proof, export_proof_garaga, export_vk, vk_to_snarkjs};
use std::{
    io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn assert_invalid<T>(result: io::Result<T>) {
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
}

fn output(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ark-snarkjs-{}-{nonce}", std::process::id()))
        .join(format!("{name}.json"))
}

fn valid_proof() -> Proof<Bn254> {
    Proof {
        a: G1Affine::generator(),
        b: G2Affine::generator(),
        c: G1Affine::generator(),
    }
}

fn valid_vk() -> VerifyingKey<Bn254> {
    VerifyingKey {
        alpha_g1: G1Affine::generator(),
        beta_g2: G2Affine::generator(),
        gamma_g2: G2Affine::generator(),
        delta_g2: G2Affine::generator(),
        gamma_abc_g1: vec![G1Affine::generator()],
    }
}

#[test]
fn infinity_points_return_errors_without_rejecting_valid_points() {
    let path = output("infinity");
    let directory = path.parent().unwrap().to_owned();

    let mut proof = valid_proof();
    proof.a = G1Affine::zero();
    assert_invalid(export_proof(&proof, &[], &path));

    let mut proof = valid_proof();
    proof.b = G2Affine::zero();
    assert_invalid(export_proof(&proof, &[], &path));

    let mut proof = valid_proof();
    proof.c = G1Affine::zero();
    assert_invalid(export_proof_garaga(&proof, &[], &path));

    let mut vk = valid_vk();
    vk.gamma_abc_g1[0] = G1Affine::zero();
    assert_invalid(vk_to_snarkjs(&vk, 0));

    let mut vk = valid_vk();
    vk.alpha_g1 = G1Affine::zero();
    assert_invalid(export_vk(&vk, 0, &path));

    let mut vk = valid_vk();
    vk.beta_g2 = G2Affine::zero();
    assert_invalid(vk_to_snarkjs(&vk, 0));

    let mut vk = valid_vk();
    vk.gamma_g2 = G2Affine::zero();
    assert_invalid(vk_to_snarkjs(&vk, 0));

    let mut vk = valid_vk();
    vk.delta_g2 = G2Affine::zero();
    assert_invalid(vk_to_snarkjs(&vk, 0));

    assert!(!path.exists());
    assert!(!directory.exists());

    export_proof(&valid_proof(), &[], &path).unwrap();
    export_vk(&valid_vk(), 0, &path).unwrap();
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
