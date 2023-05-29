use acvm::acir::native_types::{Witness, WitnessMap};
use halo2_base::halo2_proofs::{arithmetic::Field, circuit::AssignedCell};
use std::{
    collections::{btree_map, BTreeMap},
    ops::Index,
};

#[derive(Debug, Clone, Default)]
pub struct AssignmentMap<V, F: Field>(BTreeMap<Witness, Vec<AssignedCell<V, F>>>);

impl<V, FF: Field> AssignmentMap<V, FF> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn get(&self, witness: &Witness) -> Option<&Vec<AssignedCell<V, FF>>> {
        self.0.get(witness)
    }

    pub fn get_index(&self, index: u32) -> Option<&Vec<AssignedCell<V, FF>>> {
        self.0.get(&index.into())
    }

    pub fn contains_key(&self, witness: &Witness) -> bool {
        self.0.contains_key(witness)
    }

    pub fn insert(&mut self, key: Witness, value: AssignedCell<V, FF>) {
        match self.0.get_mut(&key) {
            Some(vec) => vec.push(value),
            None => {
                self.0.insert(key, vec![value]);
                ()
            }
        };
    }
}

impl<V, FF: Field> Index<&Witness> for AssignmentMap<V, FF> {
    type Output = Vec<AssignedCell<V, FF>>;

    fn index(&self, index: &Witness) -> &Self::Output {
        &self.0[index]
    }
}

pub struct IntoIter<V, FF: Field>(btree_map::IntoIter<Witness, Vec<AssignedCell<V, FF>>>);

impl<V, FF: Field> Iterator for IntoIter<V, FF> {
    type Item = (Witness, Vec<AssignedCell<V, FF>>);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(witness, assigned_cell)| (witness, assigned_cell))
    }
}

impl<V, FF: Field> IntoIterator for AssignmentMap<V, FF> {
    type Item = (Witness, Vec<AssignedCell<V, FF>>);
    type IntoIter = IntoIter<V, FF>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

impl<V, FF: Field> From<BTreeMap<Witness, Vec<AssignedCell<V, FF>>>> for AssignmentMap<V, FF> {
    fn from(value: BTreeMap<Witness, Vec<AssignedCell<V, FF>>>) -> Self {
        Self(value)
    }
}
