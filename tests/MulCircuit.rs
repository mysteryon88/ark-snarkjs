// Groth16 test example for x * y = z (z is the public input)

#![warn(unused)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    variant_size_differences,
    stable_features,
    non_shorthand_field_patterns,
    renamed_and_removed_lints,
    unsafe_code
)]

use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::AffineRepr;
use ark_ec::pairing::Pairing;
use ark_ff::{One, PrimeField};
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::test_rng;

// Supported curves
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;

/// Simple circuit: check that x * y = z (where z is a public input).
#[derive(Clone)]
struct MulCircuit<F: PrimeField> {
    x: Option<F>,
    y: Option<F>,
    z: F, // public input
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MulCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Secret witnesses
        let x = FpVar::<F>::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y = FpVar::<F>::new_witness(cs.clone(), || {
            self.y.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Public input
        let z = FpVar::<F>::new_input(cs, || Ok(self.z))?;

        // Enforce x * y = z
        (&x * &y).enforce_equal(&z)?;
        Ok(())
    }
}

/// Run Groth16 for the selected pairing curve E.
/// `label` — just a string for logging (e.g. "Bn254", "Bls12-381").
fn run_mul_groth16_for_curve<E>(label: &str)
where
    E: Pairing + ark_snarkjs::snarkjs_common::CurveTag, // CurveTag required for snarkjs export
    <E::G1Affine as AffineRepr>::BaseField: PrimeField, // G1 base field must be a PrimeField
    <E::G2Affine as AffineRepr>::BaseField: ark_snarkjs::snarkjs_common::AsFp2, // G2 must be Fp2
    E::ScalarField: PrimeField,                         // public/secret values
{
    // Deterministic RNG for tests (use OsRng in production!)
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    println!("[{label}] Creating parameters...");

    // Setup phase
    let (pk, vk) = {
        let circuit = MulCircuit::<E::ScalarField> {
            x: None,
            y: None,
            z: E::ScalarField::one(),
        };
        Groth16::<E>::setup(circuit, &mut rng).unwrap()
    };

    let pvk = Groth16::<E>::process_vk(&vk).unwrap();

    println!("[{label}] Creating proof...");

    // Concrete values in the field
    let x_u: u128 = 641;
    let y_u: u128 = 6_700_417;

    let x_f: E::ScalarField = E::ScalarField::from(x_u);
    let y_f: E::ScalarField = E::ScalarField::from(y_u);
    let z_f: E::ScalarField = x_f * y_f; // public input

    let circuit = MulCircuit::<E::ScalarField> {
        x: Some(x_f),
        y: Some(y_f),
        z: z_f,
    };

    // (Optional) Check R1CS satisfiability
    let cs = ark_relations::r1cs::ConstraintSystem::<E::ScalarField>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(
        cs.is_satisfied().unwrap(),
        "[{label}] R1CS is not satisfied"
    );

    println!("[{label}] Verifying proof...");

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

    let public_inputs = [z_f];
    assert!(
        Groth16::<E>::verify_with_processed_vk(&pvk, &[z_f], &proof).unwrap(),
        "[{label}] Proof must verify"
    );

    println!("[{label}] Exporting...");

    let out_dir = format!("target/test-output/mul/{label}");

    // proof.json
    let proof_path = format!("{out_dir}/proof.json");
    let _proof_json =
        ark_snarkjs::export_proof::export_proof::<E, _>(&proof, &public_inputs, &proof_path)
            .unwrap();

    // verification_key.json
    let vk_path = format!("{out_dir}/verification_key.json");
    let _vk_json =
        ark_snarkjs::export_vk::export_vk::<E, _>(&vk, public_inputs.len(), &vk_path).unwrap();

    println!("[{label}] Files saved: {proof_path}, {vk_path}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul_groth16_multi_curve() {
        run_mul_groth16_for_curve::<Bn254>("Bn254");
        run_mul_groth16_for_curve::<Bls12_381>("Bls12-381");
    }
}
