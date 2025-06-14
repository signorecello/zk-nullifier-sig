use noir_bigcurve::scalar_field::ScalarField;
use noir_bigcurve::curves::bn254::{BN254, BN254Params, BN254_Fq, BN254Scalar};
use crate::curves::bn254::hash_to_curve;
use std::embedded_curve_ops::EmbeddedCurveScalar as Scalar;
use bignum::BigNum;

pub type ScalarWithOps = BN254_Fq;

global TWO_POW_128: Field = 0x100000000000000000000000000000000;
global TWO_POW_120: Field = 0x1000000000000000000000000000000;
global TWO_POW_112: Field = 0x10000000000000000000000000000;

fn __field_to_be_bytes(x: Field) -> [u8; 32] {
    let x_bytes_slice: [u8; 32] = x.to_be_bytes();
    let mut x_bytes = [0; 32];
    for i in 0..32 {
        x_bytes[i] = x_bytes_slice[i];
    }
    x_bytes
}

fn __field_to_bignum(x: Field) -> ScalarWithOps {
    let x_bytes = __field_to_be_bytes(x);
    ScalarWithOps::from_be_bytes(x_bytes)
}


unconstrained fn __get_x1_split_hint(x: ScalarWithOps) -> (u8, Field) {
    let x1_bytes: [u8; 15] = (x.get_limb(1) as Field).to_le_bytes();
    let x1_le_byte_0 = x1_bytes[0];

    let mut x1_bytes_shifted_right = [0; 14];
    for i in 0..14 {
        x1_bytes_shifted_right[i] = x1_bytes[i+1];
    }

    let mut x1_byte_shifted_right: Field = x1_bytes_shifted_right[13] as Field;
    for i in 0..13 {
        let j = 13 - 1 - i;
        x1_byte_shifted_right = x1_byte_shifted_right * 256 + x1_bytes_shifted_right[j] as Field;
    }
    (x1_le_byte_0, x1_byte_shifted_right)
}

pub(crate) fn bignum_to_scalar(x: ScalarWithOps) -> Scalar {
    // Safety: this is a valid operation because we know the limbs are < 120 bits.
    let (x1_le_byte_0, x1_byte_shifted_right) = unsafe {
        __get_x1_split_hint(x)
    };

    let x1_le_byte_0_as_field = x1_le_byte_0 as Field;

    x1_byte_shifted_right.assert_max_bit_size::<112>();

    let x1_check = x1_le_byte_0_as_field + x1_byte_shifted_right * 256;

    assert(x1_check == x.get_limb(1) as Field);

    let lo = x.get_limb(0) as Field + TWO_POW_120 * x1_le_byte_0_as_field;
    let hi = x1_byte_shifted_right + x.get_limb(2) as Field * TWO_POW_112;
    Scalar { lo, hi }
}


pub(crate) fn hash_to_curve_bn254(msg: [u8; 41]) -> BN254 {
    let p = hash_to_curve(msg);
    BN254 {
        x: __field_to_bignum(p.x),
        y: __field_to_bignum(p.y),
        is_infinity: p.is_infinite,
    }
}
