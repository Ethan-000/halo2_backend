use {
    acvm::acir::native_types::Witness,
    halo2_base::halo2_proofs::circuit::Cell,
    std::{
        collections::{btree_map, BTreeMap},
        ops::Index,
    },
};

// @todo: move to src/utils.rs

#[cfg(any(feature = "zcash_halo2", feature = "pse_halo2"))]
#[derive(Debug, Clone, Default)]
pub struct CellMap(BTreeMap<Witness, Vec<Cell>>);

#[cfg(any(feature = "zcash_halo2", feature = "pse_halo2"))]
impl CellMap {
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

impl Index<&Witness> for CellMap {
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
            .map(|(witness, cell)| (witness, cell))
    }
}

#[cfg(any(feature = "zcash_halo2", feature = "pse_halo2"))]
impl IntoIterator for CellMap {
    type Item = (Witness, Vec<Cell>);
    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

#[cfg(any(feature = "zcash_halo2", feature = "pse_halo2"))]
impl From<BTreeMap<Witness, Vec<Cell>>> for CellMap {
    fn from(value: BTreeMap<Witness, Vec<Cell>>) -> Self {
        Self(value)
    }
}
