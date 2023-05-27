# Halo2 Backend for Noir

This is a [halo2](https://zcash.github.io/halo2/) backend for the [Noir Programming Language](https://noir-lang.org/)

**WARNING: This crate is experimental and under development. Expect bugs and unoptimized circuits.**

## Acknowledgement

This crate will not be possible without 

1. [barretenberg backend](https://github.com/noir-lang/acvm-backend-barretenberg)
2. [halo2-zcash](https://github.com/zcash/halo2)
3. [halo2-pse](https://github.com/privacy-scaling-explorations/halo2)
4. [halo2-lib](https://github.com/axiom-crypto/halo2-lib)
5. the gadets and educational resources provided by the halo2 community see [awesome-halo2](https://github.com/adria0/awesome-halo2)

## Installtion

```text
git clone https://github.com/Ethan-000/noir
```

```text
git checkout demo
```

```text
cd noir/crates/nargo_cli
```

```text
cargo install --path . --locked --features axiom_halo2_backend --no-default-features
```

## Examples

cd to the `examples` folder of this crate

```text
cd add
```

to generate proof `run`

```text
nargo prove add
```

to verify proof `run`

```text
nargo verify add
```

## Features

- [ ] [halo2-zcash](https://github.com/zcash/halo2)
- [ ] [halo2-pse](https://github.com/privacy-scaling-explorations/halo2)
- [x] [halo2-axiom](https://github.com/axiom-crypto/halo2-lib)

### halo2-axiom features

- [x] arithmetic gates
- [x] range proofs
- [x] and gates

- [ ] xor
- [ ] sha256 
- [ ] blake2s 
- [ ] compute_merkle_root 
- [ ] schnorr_verify
- [ ] pedersen
- [ ] hash_to_field
- [ ] ecdsa_secp256k1
- [ ] fixed_base_scalar_mul
- [ ] keccak256

## License

This library is licensed under either of the following licenses, at your discretion.

 * [Apache License Version 2.0](LICENSE-APACHE)
 * [MIT License](LICENSE-MIT)

Unless you explicitly state otherwise, any contribution that you submit to this library shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.
