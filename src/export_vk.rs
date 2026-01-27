use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use serde::Serialize;
use serde_json::to_writer_pretty;
use std::{fs, fs::File, path::Path};

use crate::snarkjs_common::{AsFp2, CurveTag, g1_xyz, g2_xyxy_z};

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct VkJson {
    pub protocol: &'static str,
    pub curve: &'static str,
    pub nPublic: usize,

    #[serde(rename = "vk_alpha_1")]
    pub vk_alpha_1: [String; 3],

    #[serde(rename = "vk_beta_2")]
    pub vk_beta_2: [[String; 2]; 3],
    #[serde(rename = "vk_gamma_2")]
    pub vk_gamma_2: [[String; 2]; 3],
    #[serde(rename = "vk_delta_2")]
    pub vk_delta_2: [[String; 2]; 3],

    #[serde(rename = "IC")]
    pub ic: Vec<[String; 3]>,
}

pub fn vk_to_snarkjs<E>(vk: &VerifyingKey<E>, n_public: usize) -> VkJson
where
    E: Pairing + CurveTag,
    <E::G1Affine as ark_ec::AffineRepr>::BaseField: PrimeField,
    <E::G2Affine as ark_ec::AffineRepr>::BaseField: AsFp2,
{
    VkJson {
        protocol: "groth16",
        curve: E::NAME,
        nPublic: n_public,

        vk_alpha_1: g1_xyz(&vk.alpha_g1),
        vk_beta_2: g2_xyxy_z(&vk.beta_g2),
        vk_gamma_2: g2_xyxy_z(&vk.gamma_g2),
        vk_delta_2: g2_xyxy_z(&vk.delta_g2),

        ic: vk.gamma_abc_g1.iter().map(g1_xyz).collect(),
    }
}

pub fn export_vk<E, P>(
    vk: &VerifyingKey<E>,
    n_public: usize,
    out_path: P,
) -> std::io::Result<VkJson>
where
    P: AsRef<Path>,
    E: Pairing + CurveTag,
    <E::G1Affine as ark_ec::AffineRepr>::BaseField: PrimeField,
    <E::G2Affine as ark_ec::AffineRepr>::BaseField: AsFp2,
{
    let json = vk_to_snarkjs::<E>(vk, n_public);

    if let Some(parent) = out_path.as_ref().parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(out_path)?;
    to_writer_pretty(file, &json).map_err(std::io::Error::other)?;

    Ok(json)
}
