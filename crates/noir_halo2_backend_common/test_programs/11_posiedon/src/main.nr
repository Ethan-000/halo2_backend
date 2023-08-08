use dep::std;
fn main(preimage: [Field; 2], hash: pub Field) {
    let computed_hash = std::hash::poseidon::bn254::hash_2(preimage);
    assert(hash == computed_hash);
}
