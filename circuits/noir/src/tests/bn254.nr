use crate::curves::bn254::hash_to_curve;
use crate::{Plume, PlumeVerifier};
use noir_bigcurve::curves::bn254::{BN254, BN254Params, BN254_Fq, BN254Scalar};
use std::embedded_curve_ops::{multi_scalar_mul};
use std::embedded_curve_ops::EmbeddedCurvePoint as Point;
use std::embedded_curve_ops::EmbeddedCurveScalar as Scalar;
use std::embedded_curve_ops::EmbeddedCurvePoint;
use std::hash::poseidon2::Poseidon2::hash;
use noir_bigcurve::scalar_field::{ScalarFieldTrait};
use bignum::BigNum;
use crate::utils::{ScalarWithOps, __field_to_bignum, bignum_to_scalar, hash_to_curve_bn254};

// let sk_f = 0x1234;
// let msg = [0x2345; 1];
// // TODO: replace BigNum<3, BNParams> with ScalarWithOps and see it break, and open an issue on github.
// let r: ScalarWithOps = BigNum::from_array([0x1234, 0x1234, 0x12]);

global G: EmbeddedCurvePoint = Point { x: 1, y: 17631683881184975370165255887551781615748388533673675138860, is_infinite: false };

unconstrained fn __field_to_bool(x: Field) -> bool {
    x as bool
}


fn compute_H<let N: u32, let N_PLUS_2: u32>(msg: [u8; N], Pk: Point) -> Point {
    // static_assert(N_PLUS_2 == N + 2); // try again when you upgrade the version of nargo.
    let mut input: [u8; N_PLUS_2] = [0; N_PLUS_2];
    for i in 0..N {
        input[i] = msg[0];
    }
    input[N] = Pk.x as u8;
    input[N+1] = Pk.y as u8;
    hash_to_curve(input)
}



fn poseidon2_points<let N: u32, let TWO_N: u32>(points: [Point; N]) -> Field {
    // static_assert(TWO_N == 2 * N);
    let mut input: [Field; TWO_N] = [0; TWO_N];
    for i in 0..N {
        let j = 2 * i;
        input[j] = points[i].x;
        input[j + 1] = points[i].y;
    }
    hash(input, N)
    // Compressing the points costs a fortune because of the check for each point that y < (p-1)/2 (each comparison costs ~190 gates).
    // poseidon2_hash(compress_points::<_, N_PLUS_1>(points))
}

// For testing only!
unconstrained pub fn compute_nullifier(sk: Scalar, H: Point) -> Point {
    multi_scalar_mul([H], [sk])
}


#[test]
fn test_plume_v2_bn254() {
    let msg: [u8; 8] = [115, 105, 103, 110, 84, 104, 105, 115];

    let sk_f = 0x1234;

    let sk: Scalar = Scalar::from_field(sk_f);
    let sk_n: ScalarWithOps = __field_to_bignum(sk_f);
    let r_n: ScalarWithOps = BN254_Fq::from_limbs([0x1234, 0x1234, 0x12]);
    let r: Scalar = bignum_to_scalar(r_n);

    let Pk: Point = multi_scalar_mul([G], [sk]);
    let H = compute_H::<8, 8 + 2>(msg, Pk);

    let Nullifier: Point = unsafe { compute_nullifier(sk, H) };

    let rG: Point = multi_scalar_mul([G], [r]);
    let rH: Point = multi_scalar_mul([H], [r]);

    let rG: Point = multi_scalar_mul([G], [r]);
    let rH: Point = multi_scalar_mul([H], [r]);

    let A = Pk;
    let B = Nullifier;
    let A2 = rG;
    let B2 = rH;

    let c_f: Field = poseidon2_points::<6, 2 * 6>([G, H, A, B, A2, B2]);
    let c_n: ScalarWithOps = __field_to_bignum(c_f);
    let c = BN254Scalar::from_bignum(c_n);

    let s_n: ScalarWithOps = r_n + (sk_n * c_n);
    let s = BN254Scalar::from_bignum(s_n);

    let pk = BN254 { x: __field_to_bignum(Pk.x), y: __field_to_bignum(Pk.y), is_infinity: Pk.is_infinite };
    let nullifier = BN254 { x: __field_to_bignum(Nullifier.x), y: __field_to_bignum(Nullifier.y), is_infinity: Nullifier.is_infinite };
    
    let plume = Plume::new(msg, c, s, pk, nullifier, hash_to_curve_bn254);
    let (_, _) = plume.plume_v2();
}

