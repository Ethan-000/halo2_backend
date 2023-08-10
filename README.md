# Halo2 Backend for Noir

This is a [halo2](https://zcash.github.io/halo2/) backend for the [Noir Programming Language](https://noir-lang.org/)

Get [detailed documentation on this repository!](https://mach-34.github.io/halo2_backend_docs)

**WARNING: This crate is experimental and under development. Expect bugs and unoptimized circuits.**

## Acknowledgement

This crate will not be possible without 

1. [barretenberg backend](https://github.com/noir-lang/acvm-backend-barretenberg)
2. [halo2-zcash](https://github.com/zcash/halo2)
3. [halo2-pse](https://github.com/privacy-scaling-explorations/halo2)
4. [halo2-axiom](https://github.com/axiom-crypto/halo2-lib)
5. the gadets and educational resources provided by the halo2 community see [awesome-halo2](https://github.com/adria0/awesome-halo2)

## Installtion

```text
git clone https://github.com/Mach-34/noir --branch demo-0.1.3
```

```text
cd noir
```

To install pse's halo2 as backend:

```text
cargo install --path crates/nargo_cli --locked --features pse_halo2_backend --no-default-features
```

To install axioms's halo2 as backend:

```text
cargo install --path crates/nargo_cli --locked --features axiom_halo2_backend --no-default-features
```

Notice that axiom's fork is built on pse's fork and should be similar.

## Examples

cd to the `crates/noir_halo2_backend_common/test_programs` folder of this crate and choose one of the tests/examples eg. 3_add

```text
cd 3_add
```

to generate proof run

```text
nargo prove add
```

to verify proof run

```text
nargo verify add
```

to generates a solidity verifier smart contract for the program run

```text
nargo codegen-verifier
```

## Features

- [ ] [halo2-zcash](https://github.com/zcash/halo2)
- [x] [halo2-pse](https://github.com/privacy-scaling-explorations/halo2)
- [x] [halo2-axiom](https://github.com/axiom-crypto/halo2-lib)

### halo2-pse features

- [x] arithmetic gates
- [x] range proofs
- [x] and gates

- [ ] xor
- [ ] sha256 
- [ ] blake2s 
- [ ] schnorr_verify
- [ ] pedersen
- [ ] hash_to_field
- [ ] ecdsa_secp256k1
- [ ] fixed_base_scalar_mul
- [ ] keccak256
- [ ] keccak256_variable_length 

### halo2-axiom features

- [x] arithmetic gates
- [x] range proofs
- [x] and gates

- [ ] xor
- [ ] sha256 
- [ ] blake2s 
- [ ] schnorr_verify
- [ ] pedersen
- [ ] hash_to_field
- [ ] ecdsa_secp256k1
- [ ] fixed_base_scalar_mul
- [ ] keccak256
- [ ] keccak256_variable_length 

## License

This library is licensed under either of the following licenses, at your discretion.

 * [Apache License Version 2.0](LICENSE-APACHE)
 * [MIT License](LICENSE-MIT)

Unless you explicitly state otherwise, any contribution that you submit to this library shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.
