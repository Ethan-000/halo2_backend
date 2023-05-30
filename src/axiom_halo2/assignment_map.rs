use {
    acvm::acir::native_types::Witness,
    halo2_base::halo2_proofs::{arithmetic::Field, circuit::Cell},
    std::{
        collections::{btree_map, BTreeMap},
        ops::Index,
    },
};

#[derive(Debug, Clone, Default)]
pub struct AssignmentMap(BTreeMap<Witness, Vec<Cell>>);

impl AssignmentMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn get(&self, witness: &Witness) -> Option<&Vec<Cell>> {
        self.0.get(witness)
    }

    pub fn get_index(&self, index: u32) -> Option<&Vec<Cell>> {
        self.0.get(&index.into())
    }

    pub fn contains_key(&self, witness: &Witness) -> bool {
        self.0.contains_key(witness)
    }

    pub fn insert(&mut self, key: Witness, value: Cell) {
        match self.0.get_mut(&key) {
            Some(vec) => vec.push(value),
            None => {
                self.0.insert(key, vec![value]);
                ()
            }
        };
    }
}

impl Index<&Witness> for AssignmentMap {
    type Output = Vec<Cell>;

    fn index(&self, index: &Witness) -> &Self::Output {
        &self.0[index]
    }
}

pub struct IntoIter(btree_map::IntoIter<Witness, Vec<Cell>>);

impl Iterator for IntoIter {
    type Item = (Witness, Vec<Cell>);

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|(witness, assigned_cell)| (witness, assigned_cell))
    }
}

impl IntoIterator for AssignmentMap {
    type Item = (Witness, Vec<Cell>);
    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

impl From<BTreeMap<Witness, Vec<Cell>>> for AssignmentMap {
    fn from(value: BTreeMap<Witness, Vec<Cell>>) -> Self {
        Self(value)
    }
}
