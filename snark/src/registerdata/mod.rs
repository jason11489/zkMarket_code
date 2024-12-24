use crate::Error;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::{CurveVar, GroupOpsBounds};
pub mod circuit;
#[cfg(test)]
mod tests;

pub trait MockingCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F;
    type HashParam;
    type H;
    type Output;

    fn generate_circuit<R: ark_std::rand::Rng>(
        round_constants: Self::HashParam,
        rng: &mut R,
    ) -> Result<Self::Output, Error>;
}

pub struct Data_size {
    pub N: usize,
    pub M: usize,
    pub Data_size: usize,
    pub K: usize,
    pub Key_len: usize,
}

// 64MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 1000,
//     M: 1005,
//     Data_size: 2000000,
//     K: 2000,
//     Key_len: 8000,
// };

// 36MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 1065,
//     M: 1075,
//     Data_size: 1125000,
//     K: 1065,
//     Key_len: 4473,
// };

// 32MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 1000,
//     M: 1005,
//     Data_size: 1000000,
//     K: 1000,
//     Key_len: 4000,
// };

// 4MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 363,
//     M: 364,
//     Data_size: 131072,
//     K: 363,
//     Key_len: 517,
// };

// 2MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 256,
//     M: 257,
//     Data_size: 65536,
//     K: 256,
//     Key_len: 258,
// };

// 1MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 182,
//     M: 183,
//     Data_size: 32768,
//     K: 182,
//     Key_len: 131,
// };

//0.5MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 128,
//     M: 130,
//     Data_size: 16384,
//     K: 128,
//     Key_len: 66,
// };

// 256KB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 91,
//     M: 92,
//     Data_size: 8192,
//     K: 91,
//     Key_len: 33,
// };

// 128KB
pub(crate) static DATA_SET: Data_size = Data_size {
    N: 64,
    M: 65,
    Data_size: 4096,
    K: 64,
    Key_len: 17,
};

//64KB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 46,
//     M: 56,
//     Data_size: 2048,
//     K: 46,
//     Key_len: 11,
// };

// // 32KB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 32,
//     M: 42,
//     Data_size: 1024,
//     K: 32,
//     Key_len: 7,
// };

// KEY LEN = (M * K) / 256 + 1;
// Data size = N * K
