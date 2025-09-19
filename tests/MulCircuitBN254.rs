// Groth16 test example for x * y = z (z is the public input) on Bn254

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

use ark_snarkjs::export_proof::export_proof;
use ark_snarkjs::export_vk::export_vk;

use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ff::One;
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::test_rng;

use ark_bn254::{Bn254, Fr};

/// Simple multiplication circuit: enforce x * y = z (z is public).
#[derive(Clone)]
struct MulCircuit {
    x: Option<Fr>, // secret witness
    y: Option<Fr>, // secret witness
    z: Fr,         // public input
}

impl ConstraintSynthesizer<Fr> for MulCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private witnesses
        let x = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.y.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Allocate public input
        let z = FpVar::<Fr>::new_input(cs, || Ok(self.z))?;

        // Enforce the constraint: x * y = z
        (&x * &y).enforce_equal(&z)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul_groth16_bn254() {
        // WARNING: this RNG is not cryptographically secure.
        // Use `OsRng` in production software.
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        println!("[Bn254] Creating parameters...");

        // Run setup with an "empty" circuit (no assignments)
        let empty = MulCircuit {
            x: None,
            y: None,
            z: Fr::one(),
        };
        let (pk, vk) = Groth16::<Bn254>::setup(empty, &mut rng).unwrap();
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        println!("[Bn254] Creating proof...");

        // Concrete values
        let x_u: u128 = 641;
        let y_u: u128 = 6_700_417;
        let x_f = Fr::from(x_u);
        let y_f = Fr::from(y_u);
        let z_f = x_f * y_f; // public input

        let circuit = MulCircuit {
            x: Some(x_f),
            y: Some(y_f),
            z: z_f,
        };

        // (Optional) check that the R1CS is satisfiable
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        cs.finalize();
        assert!(cs.is_satisfied().unwrap(), "[Bn254] R1CS not satisfied");

        // Generate proof
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        // Verify proof
        let public_inputs = [z_f];
        assert!(
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap(),
            "[Bn254] Proof must verify"
        );

        // Export proof.json and verification_key.json in snarkjs format
        let _ = export_proof::<ark_bn254::Bn254, _>(
            &proof,
            &public_inputs,
            "target/test-output/mulbn254/proof.json",
        );
        let _ = export_vk::<ark_bn254::Bn254, _>(
            &vk,
            public_inputs.len(),
            "target/test-output/mulbn254/verification_key.json",
        );

        println!("[Bn254] Done.");
    }
}
