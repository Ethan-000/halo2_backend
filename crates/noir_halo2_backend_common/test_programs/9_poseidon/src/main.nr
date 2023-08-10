use dep::std;
fn main(preimage: [Field; 2], hash: Field) {
    let computed_hash = std::hash::poseidon::bn254::hash_2(preimage);
    std::println(computed_hash);
    assert(hash == computed_hash);
}
