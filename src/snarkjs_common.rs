use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

/// Curve marker used to tag curve type for snarkjs compatibility.
pub trait CurveTag {
    const NAME: &'static str;
}

impl CurveTag for ark_bn254::Bn254 {
    const NAME: &'static str = "bn128";
}
impl CurveTag for ark_bls12_381::Bls12_381 {
    const NAME: &'static str = "bls12381";
}

/// Trait to access c0/c1 components of quadratic extension fields (Fp2).
pub trait AsFp2 {
    type Base: PrimeField;
    fn c0_c1(&self) -> (&Self::Base, &Self::Base);
}

impl<P> AsFp2 for ark_ff::fields::models::QuadExtField<P>
where
    P: ark_ff::fields::models::quadratic_extension::QuadExtConfig,
    P::BaseField: PrimeField,
{
    type Base = P::BaseField;
    fn c0_c1(&self) -> (&Self::Base, &Self::Base) {
        (&self.c0, &self.c1)
    }
}

/// Convert a field element to decimal string (snarkjs expects decimal format).
pub fn f_to_dec<F: PrimeField>(f: &F) -> String {
    let bi = f.into_bigint();
    BigUint::from_bytes_be(&bi.to_bytes_be()).to_str_radix(10)
}

/// Convert a G1 point to string array [x, y].
pub fn g1_xy<G>(p: &G) -> [String; 2]
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    let (x, y) = p.xy().expect("G1 point at infinity?");
    [f_to_dec(&x), f_to_dec(&y)]
}

/// Convert a G2 point to nested string array [[x.c0, x.c1], [y.c0, y.c1]].
pub fn g2_xyxy<G>(p: &G) -> [[String; 2]; 2]
where
    G: AffineRepr,
    G::BaseField: AsFp2,
{
    let (x, y) = p.xy().expect("G2 point at infinity?");
    let (x0, x1) = x.c0_c1();
    let (y0, y1) = y.c0_c1();
    [[f_to_dec(x0), f_to_dec(x1)], [f_to_dec(y0), f_to_dec(y1)]]
}
