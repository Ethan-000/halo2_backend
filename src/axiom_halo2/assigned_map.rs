use acvm::acir::native_types::Witness;
use halo2_base::{utils::ScalarField, AssignedValue, Context};
use std::{
    collections::{btree_map, BTreeMap},
    ops::Index,
};

// TODO: move to src/utils.rs
#[derive(Debug, Clone, Default)]
pub struct AssignedMap<F: ScalarField>(BTreeMap<Witness, Vec<AssignedValue<F>>>);

impl<F: ScalarField> AssignedMap<F> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn get(&self, witness: &Witness) -> Option<&Vec<AssignedValue<F>>> {
        self.0.get(witness)
    }

    pub fn get_index(&self, index: u32) -> Option<&Vec<AssignedValue<F>>> {
        self.0.get(&index.into())
    }

    pub fn contains_key(&self, witness: &Witness) -> bool {
        self.0.contains_key(witness)
    }

    pub fn insert(&mut self, key: Witness, value: AssignedValue<F>) {
        match self.0.get_mut(&key) {
            Some(vec) => vec.push(value),
            None => {
                self.0.insert(key, vec![value]);
            }
        };
    }

    /**
     * Check if a given witness is stored as an assigned value.
     *   - if the witness key exists, return the last assigned value
     *   - otherwise, assign the value, store it, and return it
     *
     * @param ctx - the context for the region the witness would be assigned to
     * @param key - the witness index to check for
     * @param value - the value to assign to the witness if it does not exist
     * @return - the assigned value for the witness
     */
    pub fn get_or_assign(
        &mut self,
        ctx: &mut Context<F>,
        key: &Witness,
        value: F,
    ) -> AssignedValue<F> {
        if self.contains_key(key) {
            *self.get(key).unwrap().last().unwrap()
        } else {
            let assigned = ctx.load_witness(value);
            self.insert(*key, assigned);
            assigned
        }
    }

    // /// Check if a given acir witness index needs a copy constraint when assigning a witness to a halo2 cell.
    // /// If so, perform an equality constraint on a given cell if a given witness appears in the assignment map
    // //
    // // @param ctx - the context for the region being assigned to
    // // @param assignments - the assignment map of acir witness index to exsiting halo2 cells storing witness assignments
    // // @param witness - the acir witness index to check for
    // // @param cell - the newly assigned cell to copy constrain with a cell stored in the assignment map
    // // @return - success if copy constraint operation succeeds
    // pub fn check_and_copy(
    //     &self,
    //     ctx: &mut RegionCtx<F>,
    //     witness: u32,
    //     cell: &AssignedCell<F, F>,
    // ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
    //     if self.contains_key(&Witness(witness)) {
    //         let witness_cell = self.get_index(witness).unwrap().last().unwrap();
    //         ctx.constrain_equal(witness_cell.cell(), cell.cell())
    //     } else {
    //         Ok(())
    //     }
    // }
}

impl<F: ScalarField> Index<&Witness> for AssignedMap<F> {
    type Output = Vec<AssignedValue<F>>;

    fn index(&self, index: &Witness) -> &Self::Output {
        &self.0[index]
    }
}

pub struct IntoIter<F: ScalarField>(btree_map::IntoIter<Witness, Vec<AssignedValue<F>>>);

impl<F: ScalarField> Iterator for IntoIter<F> {
    type Item = (Witness, Vec<AssignedValue<F>>);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(witness, cell)| (witness, cell))
    }
}

impl<F: ScalarField> IntoIterator for AssignedMap<F> {
    type Item = (Witness, Vec<AssignedValue<F>>);
    type IntoIter = IntoIter<F>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

impl<F: ScalarField> From<BTreeMap<Witness, Vec<AssignedValue<F>>>> for AssignedMap<F> {
    fn from(value: BTreeMap<Witness, Vec<AssignedValue<F>>>) -> Self {
        Self(value)
    }
}
