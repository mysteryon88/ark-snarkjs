use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::Proof;
use serde::Serialize;
use serde_json::to_writer_pretty;
use std::{fs, fs::File, path::Path};

use crate::snarkjs_common::{AsFp2, CurveTag, f_to_dec, g1_xy, g2_xyxy};

/// JSON structure for Groth16 proof in `snarkjs`-compatible format.
#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct ProofJson {
    pub protocol: &'static str,     // always "groth16"
    pub curve: &'static str,        // "bn128" or "bls12381"
    pub pi_a: [String; 3],          // G1 point [x, y, 1]
    pub pi_b: [[String; 2]; 3],     // G2 point [[x0, x1], [y0, y1], [1, 0]]
    pub pi_c: [String; 3],          // G1 point [x, y, 1]
    pub publicSignals: Vec<String>, // array of decimal-encoded public inputs
}

/// JSON structure for Groth16 proof in `garaga`-compatible format.
#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct ProofJsonGaraga {
    pub protocol: &'static str,     // always "groth16"
    pub curve: &'static str,        // "bn128" or "bls12381"
    pub a: [String; 3],             // G1 point [x, y, 1]
    pub b: [[String; 2]; 3],        // G2 point [[x0, x1], [y0, y1], [1, 0]]
    pub c: [String; 3],             // G1 point [x, y, 1]
    pub publicSignals: Vec<String>, // array of decimal-encoded public inputs
}

/// Extract proof coordinates and convert public signals to decimal strings.
fn extract_proof_data<E>(
    proof: &Proof<E>,
    public: &[E::ScalarField],
) -> ([String; 2], [[String; 2]; 2], [String; 2], Vec<String>)
where
    E: Pairing + CurveTag,
    <E::G1Affine as ark_ec::AffineRepr>::BaseField: PrimeField,
    <E::G2Affine as ark_ec::AffineRepr>::BaseField: AsFp2,
    E::ScalarField: PrimeField,
{
    let a = g1_xy(&proof.a);
    let b = g2_xyxy(&proof.b);
    let c = g1_xy(&proof.c);
    let public_signals = public.iter().map(f_to_dec::<E::ScalarField>).collect();
    (a, b, c, public_signals)
}

/// Write a serializable JSON structure to a file, creating parent directories if needed.
fn write_json_file<T, P>(json: &T, out_path: P) -> std::io::Result<()>
where
    T: Serialize,
    P: AsRef<Path>,
{
    // Ensure parent directories exist
    if let Some(parent) = out_path.as_ref().parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    // Write pretty-printed JSON to file
    let file = File::create(out_path)?;
    to_writer_pretty(file, json).map_err(std::io::Error::other)?;
    Ok(())
}

/// Export a Groth16 proof and its public signals to `snarkjs` JSON format.
/// Writes the file to `out_path` and returns the in-memory `ProofJson`.
pub fn export_proof<E, P>(
    proof: &Proof<E>,          // Groth16 proof from arkworks
    public: &[E::ScalarField], // list of public inputs
    out_path: P,               // output path for JSON file
) -> std::io::Result<ProofJson>
where
    P: AsRef<Path>,        // accepts &str, String, Path, PathBuf
    E: Pairing + CurveTag, // curve type with snarkjs "NAME"
    <E::G1Affine as ark_ec::AffineRepr>::BaseField: PrimeField,
    <E::G2Affine as ark_ec::AffineRepr>::BaseField: AsFp2,
    E::ScalarField: PrimeField,
{
    let (a, b, c, public_signals) = extract_proof_data(proof, public);

    let json = ProofJson {
        protocol: "groth16",
        curve: E::NAME,
        pi_a: [a[0].clone(), a[1].clone(), "1".to_string()],
        pi_b: [
            [b[0][0].clone(), b[0][1].clone()],
            [b[1][0].clone(), b[1][1].clone()],
            ["1".to_string(), "0".to_string()],
        ],
        pi_c: [c[0].clone(), c[1].clone(), "1".to_string()],
        publicSignals: public_signals,
    };

    write_json_file(&json, &out_path)?;
    Ok(json)
}

/// Export a Groth16 proof and its public signals to `garaga` JSON format.
/// Writes the file to `out_path` and returns the in-memory `ProofJsonGaraga`.
pub fn export_proof_garaga<E, P>(
    proof: &Proof<E>,          // Groth16 proof from arkworks
    public: &[E::ScalarField], // list of public inputs
    out_path: P,               // output path for JSON file
) -> std::io::Result<ProofJsonGaraga>
where
    P: AsRef<Path>,        // accepts &str, String, Path, PathBuf
    E: Pairing + CurveTag, // curve type with snarkjs "NAME"
    <E::G1Affine as ark_ec::AffineRepr>::BaseField: PrimeField,
    <E::G2Affine as ark_ec::AffineRepr>::BaseField: AsFp2,
    E::ScalarField: PrimeField,
{
    let (a, b, c, public_signals) = extract_proof_data(proof, public);

    let json = ProofJsonGaraga {
        protocol: "groth16",
        curve: E::NAME,
        a: [a[0].clone(), a[1].clone(), "1".to_string()],
        b: [
            [b[0][0].clone(), b[0][1].clone()],
            [b[1][0].clone(), b[1][1].clone()],
            ["1".to_string(), "0".to_string()],
        ],
        c: [c[0].clone(), c[1].clone(), "1".to_string()],
        publicSignals: public_signals,
    };

    write_json_file(&json, &out_path)?;
    Ok(json)
}
