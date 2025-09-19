use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use serde::Serialize;
use serde_json::to_writer_pretty;
use std::{fs, fs::File, path::Path};

use crate::snarkjs_common::{AsFp2, CurveTag, g1_xy, g2_xyxy};

/// JSON structure for Groth16 verifying key in `snarkjs`-compatible format.
#[derive(Serialize)]
pub struct VkJson {
    pub protocol: &'static str, // always "groth16"
    pub curve: &'static str,    // "bn128" or "bls12381"
    pub n_public: usize,        // number of public inputs

    #[serde(rename = "vk_alpha_1")]
    pub vk_alpha_1: [String; 2], // G1 point
    #[serde(rename = "vk_beta_2")]
    pub vk_beta_2: [[String; 2]; 2], // G2 point
    #[serde(rename = "vk_gamma_2")]
    pub vk_gamma_2: [[String; 2]; 2], // G2 point
    #[serde(rename = "vk_delta_2")]
    pub vk_delta_2: [[String; 2]; 2], // G2 point
    #[serde(rename = "IC")]
    pub ic: Vec<[String; 2]>, // list of G1 points for input coefficients
}

/// Convert a Groth16 verifying key to `snarkjs` JSON format (in-memory only).
pub fn vk_to_snarkjs<E>(vk: &VerifyingKey<E>, n_public: usize) -> VkJson
where
    E: Pairing + CurveTag,
    <E::G1Affine as ark_ec::AffineRepr>::BaseField: PrimeField,
    <E::G2Affine as ark_ec::AffineRepr>::BaseField: AsFp2,
{
    VkJson {
        protocol: "groth16",
        curve: E::NAME,
        n_public,
        vk_alpha_1: g1_xy(&vk.alpha_g1),
        vk_beta_2: g2_xyxy(&vk.beta_g2),
        vk_gamma_2: g2_xyxy(&vk.gamma_g2),
        vk_delta_2: g2_xyxy(&vk.delta_g2),
        ic: vk.gamma_abc_g1.iter().map(g1_xy).collect(),
    }
}

/// Export a Groth16 verifying key to `snarkjs` JSON format.
/// Writes the file to `out_path` and returns the in-memory `VkJson`.
pub fn export_vk<E, P>(
    vk: &VerifyingKey<E>, // Groth16 verifying key from arkworks
    n_public: usize,      // number of public inputs
    out_path: P,          // output path for JSON file
) -> std::io::Result<VkJson>
where
    P: AsRef<Path>, // accepts &str, String, Path, PathBuf
    E: Pairing + CurveTag,
    <E::G1Affine as ark_ec::AffineRepr>::BaseField: PrimeField,
    <E::G2Affine as ark_ec::AffineRepr>::BaseField: AsFp2,
{
    // Build JSON structure in memory
    let json = vk_to_snarkjs::<E>(vk, n_public);

    // Ensure parent directories exist
    if let Some(parent) = out_path.as_ref().parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    // Write pretty-printed JSON to file
    let file = File::create(out_path)?;
    to_writer_pretty(file, &json).map_err(std::io::Error::other)?;

    Ok(json)
}
