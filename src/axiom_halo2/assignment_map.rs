use acvm::acir::native_types::{Witness, WitnessMap};
use halo2_base::halo2_proofs::{arithmetic::Field, circuit::AssignedCell};
use std::{
    collections::{btree_map, BTreeMap},
    ops::Index,
};

#[derive(Debug)]
pub struct AssignmentMap<V, F: Field>(BTreeMap<Witness, Vec<AssignedCell<V, F>>>);

impl<V, F: Field> AssignmentMap<V, F> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn get(&self, witness: &Witness) -> Option<&Vec<AssignedCell<V, F>>> {
        self.0.get(witness)
    }

    pub fn get_index(&self, index: u32) -> Option<&Vec<AssignedCell<V, F>>> {
        self.0.get(&index.into())
    }

    pub fn contains_key(&self, witness: &Witness) -> bool {
        self.0.contains_key(witness)
    }

    pub fn insert(&mut self, key: Witness, value: AssignedCell<V, F>) {
        match self.0.get_mut(&key) {
            Some(vec) => vec.push(value),
            None => {
                self.0.insert(key, vec![value]);
                ()
            }
        };
    }
}

impl<V, F: Field> Index<&Witness> for AssignmentMap<V, F> {
    type Output = Vec<AssignedCell<V, F>>;

    fn index(&self, index: &Witness) -> &Self::Output {
        &self.0[index]
    }
}

pub struct IntoIter<V, F: Field>(btree_map::IntoIter<Witness, Vec<AssignedCell<V, F>>>);

impl<V, F: Field> Iterator for IntoIter<V, F> {
    type Item = (Witness, Vec<AssignedCell<V, F>>);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(witness, assigned_cell)| (witness, assigned_cell))
    }
}

impl<V, F: Field> IntoIterator for AssignmentMap<V, F> {
    type Item = (Witness, Vec<AssignedCell<V, F>>);
    type IntoIter = IntoIter<V, F>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

impl<V, F: Field> From<BTreeMap<Witness, Vec<AssignedCell<V, F>>>> for AssignmentMap<V, F> {
    fn from(value: BTreeMap<Witness, Vec<AssignedCell<V, F>>>) -> Self {
        Self(value)
    }
}
