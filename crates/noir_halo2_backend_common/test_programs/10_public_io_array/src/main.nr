// Test arrays to see if a public array of length 3 has values that sum to 
// the sum of values in an array of length 20 
fn main(priv_array: [Field; 20], pub_array: pub [Field; 3]) {
    let mut priv_sum = 0;
    let mut pub_sum = 0;
    // Sum private
    for i in 0..20 {
        priv_sum += priv_array[i];
    }
    // Sum public
    for j in 0..3 {
        pub_sum += pub_array[j];
    }

    assert(priv_sum == pub_sum);
}
