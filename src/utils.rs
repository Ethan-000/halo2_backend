use acvm::acir::native_types::Witness;

pub trait Secp256k1FieldConversion {
    type Base;
    type Scalar;

    fn noir_field_to_secp255k1_fp_field(&self, limbs: Vec<Witness>) -> Self::Base;

    fn noir_field_to_secp255k1_fq_field(&self, limbs: Vec<Witness>) -> Self::Scalar;
}

#[macro_export]
macro_rules! noir_field_to_halo2_field {
    (
        $halo2_field:ty
    ) => {
        fn noir_field_to_halo2_field(noir_ele: FieldElement) -> $halo2_field {
            let mut bytes = noir_ele.to_be_bytes();
            bytes.reverse();
            let mut halo_ele: [u8; 32] = [0; 32];
            halo_ele[..bytes.len()].copy_from_slice(&bytes[..]);
            <$halo2_field>::from_bytes(&halo_ele).unwrap()
        }
    };
}

#[macro_export]
macro_rules! impl_noir_field_to_secp255k1_field_conversion {
    (
        $name:ident,
        $original_scalar_field:ty,
        $curve_base_field:ty,
        $curve_scalar_field:ty
    ) => {
        impl Secp256k1FieldConversion for $name<$original_scalar_field> {
            type Base = $curve_base_field;
            type Scalar = $curve_scalar_field;

            fn noir_field_to_secp255k1_fp_field(&self, limbs: Vec<Witness>) -> Self::Base {
                let binding: Vec<u8> = limbs
                    .into_iter()
                    .map(|w| *self.witness_values.get(&w).unwrap_or(&FieldElement::zero()))
                    .flat_map(|ele| ele.to_be_bytes())
                    .collect::<Vec<u8>>();

                let mut element_bytes = [0u8; 32];
                let mut element_vec: Iter<u8> = binding.iter();
                for byte in element_bytes.iter_mut() {
                    *byte = *element_vec.next().unwrap();
                }

                Self::Base::from_bytes(&element_bytes).unwrap()
            }

            fn noir_field_to_secp255k1_fq_field(&self, limbs: Vec<Witness>) -> Self::Scalar {
                let binding: Vec<u8> = limbs
                    .into_iter()
                    .map(|w| *self.witness_values.get(&w).unwrap_or(&FieldElement::zero()))
                    .flat_map(|ele| ele.to_be_bytes())
                    .collect::<Vec<u8>>();

                let mut element_bytes = [0u8; 32];
                let mut element_vec: Iter<u8> = binding.iter();
                for byte in element_bytes.iter_mut() {
                    *byte = *element_vec.next().unwrap();
                }

                Self::Scalar::from_bytes(&element_bytes).unwrap()
            }
        }
    };
}
