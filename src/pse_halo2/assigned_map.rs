use {
    acvm::acir::native_types::Witness,
    std::{
        collections::{btree_map, BTreeMap},
        ops::Index,
    },
};

// #[cfg(all(feature = "axiom_halo2", not(any(feature = "pse_halo2", feature = "zcash_halo2"))))]
// use halo2_base::halo2_proofs::circuit::Cell;

// #[cfg(all(feature = "pse_halo2", not(any(feature = "axiom_halo2", feature = "zcash_halo2"))))]
// use pse_halo2wrong::halo2::circuit::Cell;
use pse_halo2wrong::halo2::{
    circuit::AssignedCell,
    arithmetic::Field
};

// // #[cfg(all(feature = "zcash_halo2", not(any(feature = "axiom_halo2", feature = "pse_halo2"))))]
// use zcash_halo2_proofs::circuit::Cell;

// @todo: move to src/utils.rs

#[derive(Debug, Clone, Default)]
pub struct AssignedMap<F: Field>(BTreeMap<Witness, Vec<AssignedCell<F, F>>>);

// #[cfg(any(feature = "zcash_halo2", feature = "pse_halo2"))]
impl<F: Field> AssignedMap<F> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn get(&self, witness: &Witness) -> Option<&Vec<AssignedCell<F, F>>> {
        self.0.get(witness)
    }

    pub fn get_index(&self, index: u32) -> Option<&Vec<AssignedCell<F, F>>> {
        self.0.get(&index.into())
    }

    pub fn contains_key(&self, witness: &Witness) -> bool {
        self.0.contains_key(witness)
    }

    pub fn insert(&mut self, key: Witness, value: AssignedCell<F, F>) {
        match self.0.get_mut(&key) {
            Some(vec) => vec.push(value),
            None => {
                self.0.insert(key, vec![value]);
                ()
            }
        };
    }
}

impl<F: Field> Index<&Witness> for AssignedMap<F> {
    type Output = Vec<AssignedCell<F, F>>;

    fn index(&self, index: &Witness) -> &Self::Output {
        &self.0[index]
    }
}

pub struct IntoIter<F: Field>(btree_map::IntoIter<Witness, Vec<AssignedCell<F, F>>>);

impl<F: Field> Iterator for IntoIter<F> {
    type Item = (Witness, Vec<AssignedCell<F, F>>);

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|(witness, cell)| (witness, cell))
    }
}

// #[cfg(any(feature = "zcash_halo2", feature = "pse_halo2"))]
impl<F: Field> IntoIterator for AssignedMap<F> {
    type Item = (Witness, Vec<AssignedCell<F, F>>);
    type IntoIter = IntoIter<F>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

// #[cfg(any(feature = "zcash_halo2", feature = "pse_halo2"))]
impl<F: Field> From<BTreeMap<Witness, Vec<AssignedCell<F, F>>>> for AssignedMap<F> {
    fn from(value: BTreeMap<Witness, Vec<AssignedCell<F, F>>>) -> Self {
        Self(value)
    }
}
