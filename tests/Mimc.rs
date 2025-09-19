// https://github.com/arkworks-rs/groth16/blob/b3b4a152b2f379930011ad0699b710d3746a552e/tests/mimc.rs
// Sample based on arkworks, Groth16 + MiMC
// Supports multiple curves via generic E: Pairing (Bn254 and Bls12_381)

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

use ark_snarkjs;

use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::test_rng;

// Concrete curves
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;

const MIMC_ROUNDS: usize = 322;

/// LongsightF322p3 MiMC function (xL, xR) -> xL, over an arbitrary field F.
/// xl, xr and constants operate over F = E::ScalarField for the selected curve E.
fn mimc<F: Field>(mut xl: F, mut xr: F, constants: &[F]) -> F {
    assert_eq!(constants.len(), MIMC_ROUNDS);
    for i in 0..MIMC_ROUNDS {
        let mut tmp1 = xl;
        tmp1.add_assign(&constants[i]);
        let mut tmp2 = tmp1;
        tmp2.square_in_place();
        tmp2.mul_assign(&tmp1);
        tmp2.add_assign(&xr);
        xr = xl;
        xl = tmp2;
    }
    xl
}

/// Demo MiMC circuit for proving knowledge of a preimage — generic over the field.
#[derive(Copy, Clone)]
struct MiMCDemo<'a, F: Field> {
    xl: Option<F>,
    xr: Option<F>,
    output: Option<F>,
    constants: &'a [F],
}

impl<'a, F: PrimeField> ConstraintSynthesizer<F> for MiMCDemo<'a, F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Secret witnesses
        let mut xl = FpVar::new_witness(cs.clone(), || {
            self.xl.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mut xr = FpVar::new_witness(cs.clone(), || {
            self.xr.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Public input: hash (image)
        let output = FpVar::new_input(cs.clone(), || {
            self.output.ok_or(SynthesisError::AssignmentMissing)
        })?;

        for i in 0..MIMC_ROUNDS {
            // tmp = (xL + Ci)^2
            let tmp = (&xl + self.constants[i]).square()?;

            // new_xL = xR + (xL + Ci)^3
            let new_xl = tmp * (&xl + self.constants[i]) + xr;

            // xR = xL
            xr = xl;
            // xL = new_xL
            xl = new_xl;
        }

        // Enforce that the final output matches the expected image
        output.enforce_equal(&xl)?;
        Ok(())
    }
}

/// Run MiMC Groth16 demo for a selected curve E: Pairing.
/// `label` — just a tag for logging (e.g. "Bn254" or "Bls12-381").
fn run_mimc_groth16_for_curve<E>(label: &str)
where
    E: Pairing + ark_snarkjs::snarkjs_common::CurveTag, // CurveTag provides snarkjs name
    <E::G1Affine as AffineRepr>::BaseField: PrimeField, // G1 base field must be PrimeField
    <E::G2Affine as AffineRepr>::BaseField: ark_snarkjs::snarkjs_common::AsFp2, // G2 is Fp2
    E::ScalarField: PrimeField,                         // scalar field for witnesses/inputs
{
    // WARNING: this RNG is not cryptographically safe!
    // Use `OsRng` in production systems.
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let constants: Vec<E::ScalarField> = (0..MIMC_ROUNDS)
        .map(|_| E::ScalarField::rand(&mut rng))
        .collect();

    println!("[{label}] Creating parameters...");

    let (pk, vk) = {
        let circuit = MiMCDemo::<E::ScalarField> {
            xl: None,
            xr: None,
            output: None,
            constants: &constants,
        };
        Groth16::<E>::setup(circuit, &mut rng).unwrap()
    };

    let pvk = Groth16::<E>::process_vk(&vk).unwrap();

    println!("[{label}] Creating proof...");

    let xl = E::ScalarField::rand(&mut rng);
    let xr = E::ScalarField::rand(&mut rng);
    let image = mimc::<E::ScalarField>(xl, xr, &constants);

    let circuit = MiMCDemo::<E::ScalarField> {
        xl: Some(xl),
        xr: Some(xr),
        output: Some(image),
        constants: &constants,
    };

    let cs = ark_relations::r1cs::ConstraintSystem::<E::ScalarField>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(cs.is_satisfied().unwrap());

    println!("[{label}] Verifying proof...");

    let public_inputs = [image];

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();
    assert!(
        Groth16::<E>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap(),
        "[{label}] Proof must verify"
    );

    println!("[{label}] Exporting...");

    let out_dir = format!("target/test-output/mimc/{label}");

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
    fn test_mimc_groth16_multi_curve() {
        run_mimc_groth16_for_curve::<Bn254>("Bn254");
        run_mimc_groth16_for_curve::<Bls12_381>("Bls12-381");
    }
}
