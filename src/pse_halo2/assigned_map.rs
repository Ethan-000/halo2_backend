use acvm::acir::native_types::Witness;
use pse_halo2wrong::{
    halo2::{arithmetic::Field, circuit::AssignedCell},
    RegionCtx,
};
use std::{
    collections::{btree_map, BTreeMap},
    ops::Index,
};

#[derive(Debug, Clone, Default)]
pub struct AssignedMap<F: Field>(BTreeMap<Witness, Vec<AssignedCell<F, F>>>);

impl<F: Field> AssignedMap<F> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    #[allow(dead_code)]
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
            }
        };
    }

    /// Check if a given acir witness index needs a copy constraint when assigning a witness to a halo2 cell.
    /// If so, perform an equality constraint on a given cell if a given witness appears in the assignment map
    //
    // @param ctx - the context for the region being assigned to
    // @param assignments - the assignment map of acir witness index to exsiting halo2 cells storing witness assignments
    // @param witness - the acir witness index to check for
    // @param cell - the newly assigned cell to copy constrain with a cell stored in the assignment map
    // @return - success if copy constraint operation succeeds
    pub fn check_and_copy(
        &self,
        ctx: &mut RegionCtx<F>,
        witness: u32,
        cell: &AssignedCell<F, F>,
    ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
        if self.contains_key(&Witness(witness)) {
            let witness_cell = self.get_index(witness).unwrap().last().unwrap();
            ctx.constrain_equal(witness_cell.cell(), cell.cell())
        } else {
            Ok(())
        }
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
        self.0.next().map(|(witness, cell)| (witness, cell))
    }
}

impl<F: Field> IntoIterator for AssignedMap<F> {
    type Item = (Witness, Vec<AssignedCell<F, F>>);
    type IntoIter = IntoIter<F>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

impl<F: Field> From<BTreeMap<Witness, Vec<AssignedCell<F, F>>>> for AssignedMap<F> {
    fn from(value: BTreeMap<Witness, Vec<AssignedCell<F, F>>>) -> Self {
        Self(value)
    }
}
