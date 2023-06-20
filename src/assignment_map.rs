use acvm::acir::native_types::Witness;

#[cfg(feautre = "axiom_halo2")]
use {
    halo2_base::{
        utils::ScalarField,
        halo2_proofs::{
            arithmetic::Field,
            circuit::{AssignedCell, Region},
        },
    },
    halo2_ecc::fields::PrimeField,
};
use halo2_base::AssignedValue;
#[cfg(feature = "pse_halo2")]
use pse_halo2wrong::{
    curves::group::ff::PrimeField,
    RegionCtx,
    halo2::circuit::AssignedCell
};

use std::{
    collections::{btree_map, BTreeMap},
    ops::Index,
};

pub mod Cell {

    use super::*;

    #[derive(Debug, Clone, Default)]
    pub struct AssignedCellMap<F: PrimeField>(BTreeMap<Witness, Vec<AssignedCell<F, F>>>);
    
    impl<F: PrimeField> AssignedCellMap<F> {
        pub fn new() -> Self {
            Self(BTreeMap::new())
        }
    
        pub fn _get(&self, witness: &Witness) -> Option<&Vec<AssignedCell<F, F>>> {
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
    
        // Check if a given acir witness index needs a copy constraint when assigning a witness to a halo2 cell.
        // If so, perform an equality constraint on a given cell if a given witness appears in the assignment map
        //
        // @param ctx - the context for the region being assigned to
        // @param assignments - the assignment map of acir witness index to exsiting halo2 cells storing witness assignments
        // @param witness - the acir witness index to check for
        // @param cell - the newly assigned cell to copy constrain with a cell stored in the assignment map
        // @return - success if copy constraint operation succeeds
        #[cfg(feature = "pse_halo2")]
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
    
        #[cfg(feature = "axiom_halo2")]
        pub fn check_and_copy(
            &self,
            region: &mut Region<F>,
            witness: u32,
            cell: &AssignedCell<F, F>,
        ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
            if self.contains_key(&Witness(witness)) {
                let witness_cell = self.get_index(witness).unwrap().last().unwrap();
                Ok(region.constrain_equal(witness_cell.cell(), cell.cell()))
            } else {
                Ok(())
            }
        }
    }
    
    impl<F: PrimeField> Index<&Witness> for AssignedCellMap<F> {
        type Output = Vec<AssignedCell<F, F>>;
    
        fn index(&self, index: &Witness) -> &Self::Output {
            &self.0[index]
        }
    }
    
    pub struct IntoIter<F: PrimeField>(btree_map::IntoIter<Witness, Vec<AssignedCell<F, F>>>);
    
    impl<F: PrimeField> Iterator for IntoIter<F> {
        type Item = (Witness, Vec<AssignedCell<F, F>>);
    
        fn next(&mut self) -> Option<Self::Item> {
            self.0.next().map(|(witness, cell)| (witness, cell))
        }
    }
    
    impl<F: PrimeField> IntoIterator for AssignedCellMap<F> {
        type Item = (Witness, Vec<AssignedCell<F, F>>);
        type IntoIter = IntoIter<F>;
    
        fn into_iter(self) -> Self::IntoIter {
            IntoIter(self.0.into_iter())
        }
    }
    
    impl<F: PrimeField> From<BTreeMap<Witness, Vec<AssignedCell<F, F>>>> for AssignedCellMap<F> {
        fn from(value: BTreeMap<Witness, Vec<AssignedCell<F, F>>>) -> Self {
            Self(value)
        }
    }
}

// #[cfg(feautre = "axiom_halo2")]
pub mod Value {

    use super::*;
    use halo2_base::{
        AssignedValue,
        utils::value_to_option,
        halo2_proofs::plonk::Assigned,
    };

    #[derive(Debug, Clone, Default)]
    pub struct AssignedValueMap<F: PrimeField>(BTreeMap<Witness, Vec<AssignedValue<F>>>);
    
    impl<F: PrimeField> AssignedValueMap<F> {
        pub fn new() -> Self {
            Self(BTreeMap::new())
        }
    
        pub fn _get(&self, witness: &Witness) -> Option<&Vec<AssignedValue<F>>> {
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
    
        // Check if a given acir witness index needs a copy constraint when assigning a witness to a halo2 cell.
        // If so, perform an equality constraint on a given cell if a given witness appears in the assignment map
        //
        // @param ctx - the context for the region being assigned to
        // @param assignments - the assignment map of acir witness index to exsiting halo2 cells storing witness assignments
        // @param witness - the acir witness index to check for
        // @param cell - the newly assigned cell to copy constrain with a cell stored in the assignment map
        // @return - success if copy constraint operation succeeds
        pub fn check_and_copy(
            &self,
            region: &mut Region<F>,
            witness: u32,
            cell: &AssignedCell<F, F>,
        ) -> Result<(), pse_halo2wrong::halo2::plonk::Error> {
            if self.contains_key(&Witness(witness)) {
                let witness_cell = self.get_index(witness).unwrap().last().unwrap();
                Ok(region.constrain_equal(witness_cell.cell(), cell.cell()))
            } else {
                Ok(())
            }
        }
    }
    
    impl<F: PrimeField> Index<&Witness> for AssignedValueMap<F> {
        type Output = Vec<AssignedValue<F>>;
    
        fn index(&self, index: &Witness) -> &Self::Output {
            &self.0[index]
        }
    }
    
    pub struct IntoIter<F: PrimeField>(btree_map::IntoIter<Witness, Vec<AssignedValue<F>>>);
    
    impl<F: PrimeField> Iterator for IntoIter<F> {
        type Item = (Witness, Vec<AssignedValue<F>>);
    
        fn next(&mut self) -> Option<Self::Item> {
            self.0.next().map(|(witness, cell)| (witness, cell))
        }
    }
    
    impl<F: PrimeField> IntoIterator for AssignedValueMap<F> {
        type Item = (Witness, Vec<AssignedValueMap<F>>);
        type IntoIter = IntoIter<F>;
    
        fn into_iter(self) -> Self::IntoIter {
            IntoIter(self.0.into_iter())
        }
    }
    
    impl<F: PrimeField> From<BTreeMap<Witness, Vec<AssignedValue<F>>>> for AssignedValueMap<F> {
        fn from(value: BTreeMap<Witness, Vec<AssignedValue<F>>>) -> Self {
            Self(value)
        }
    }

    impl<F: PrimeField> From<Cell::AssignedCellMap<F>> for AssignedValueMap<F> {
        fn from(value: Cell::AssignedCellMap<F>) -> Self {
            for (i, (witness, cells)) in value.into_iter().enumerate() {
                let values: Vec<Assigned<F>> = cells.iter().map(|cell| value_to_option(**cell.value())).collect();
            }
            // let cells = .map(|(i, (witness, cells))| {
            //     let value = AssignedValue::new(witness, i);
            //     (value, cells)
            // });
            // let mut assigned_value_map = AssignedValueMap::new();
            // for (witness, cells) in value.into_iter() {
            //     for cell in cells {
            //         assigned_value_map.insert(witness, value_to_option(cell));
            //     }
            // }
            // assigned_value_map
        }
    }
}

