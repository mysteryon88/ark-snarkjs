# <h1 align="center"> ark-snarkjs </h1>

Utilities for exporting [arkworks](https://arkworks.rs/) proofs and verifying keys into a format compatible with [snarkjs](https://github.com/iden3/snarkjs).
Currently supports **Groth16** on curves **BN254** and **BLS12-381**.

[![dependency status](https://deps.rs/repo/github/mysteryon88/ark-snarkjs/status.svg)](https://deps.rs/repo/github/mysteryon88/ark-snarkjs)

## Installation

```sh
cargo add ark-snarkjs
```

## Example

Here is a full example with a simple circuit, proof generation, verification, and exporting proof + verifying key into snarkjs-compatible JSON.

```rust
use ark_snarkjs::{export_proof, export_vk};

let proof_json = export_proof::<ark_bn254::Bn254, _>(
    &proof,
    &public_inputs,
    "proof.json",
);

let vk_json = export_vk::<ark_bn254::Bn254, _>(
    &vk,
    public_inputs.len(),
    "verification_key.json",
);
```

Both `proof.json` and `vk.json` are fully compatible with snarkjs, so you can directly use them with the `snarkjs verify` command.

## Supported Curves

- BN254
- BLS12-381

## License

MIT
