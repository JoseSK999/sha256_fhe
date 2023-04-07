// This module contains all the operations used in the sha256 function, implemented purely with
// boolean operations. We use multi-threading to speed up the computation, implemented in the
// "and", "xor" and "not" functions, used almost everywhere. Specifically we have set the number of
// threads to 8, although it can be changed or even replaced by more complex concurrency techniques.

use std::sync::Arc;
use std::thread;
use tfhe::boolean::prelude::{BinaryBooleanGates, Ciphertext, ServerKey};

// Carry Lookahead adder (modulo 2^32)
// 3 batches of 32 parallelized bool ops (96) + 62 sequential bool ops
pub fn add(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let propagate = xor(a, b, sk);
    let generate = and(a, b, sk);

    let carry = compute_carry(&propagate, &generate, sk);
    let sum = xor(&propagate, &carry, sk);

    sum
}

// This function could be optimized with a parallel prefix algorithm or similar
fn compute_carry(propagate: &[Ciphertext; 32], generate: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let mut carry = trivial_bools(&[false; 32], sk);
    carry[31] = sk.trivial_encrypt(false);

    for i in (0..31).rev() {
        carry[i] = sk.or(&generate[i + 1], &sk.and(&propagate[i + 1], &carry[i + 1]));
    }

    carry
}

// 2 batches of 32 parallelized bool ops (64)
pub fn sigma0(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 7, sk);
    let b = rotate_right(x, 18, sk);
    let c = shift_right(x, 3, sk);
    xor(&xor(&a, &b, sk), &c, sk)
}

pub fn sigma1(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 17, sk);
    let b = rotate_right(x, 19, sk);
    let c = shift_right(x, 10, sk);
    xor(&xor(&a, &b, sk), &c, sk)
}

pub fn sigma_upper_case_0(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 2, sk);
    let b = rotate_right(x, 13, sk);
    let c = rotate_right(x, 22, sk);
    xor(&xor(&a, &b, sk), &c, sk)
}

pub fn sigma_upper_case_1(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 6, sk);
    let b = rotate_right(x, 11, sk);
    let c = rotate_right(x, 25, sk);
    xor(&xor(&a, &b, sk), &c, sk)
}

// 0 bool ops
fn rotate_right(x: &[Ciphertext; 32], n: usize, sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = trivial_bools(&[false; 32], sk);
    for i in 0..32 {
        result[(i + n) % 32] = x[i].clone();
    }
    result
}

fn shift_right(x: &[Ciphertext; 32], n: usize, sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = trivial_bools(&[false; 32], sk);
    for i in 0..(32 - n) {
        result[i + n] = x[i].clone();
    }
    result
}

// 4 batches of 32 parallelized bool ops (128)
pub fn ch(x: &[Ciphertext; 32], y: &[Ciphertext; 32], z: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let t1 = and(x, y, sk);
    let t2 = and(&not(x, sk), z, sk);
    xor(&t1, &t2, sk)
}

// 5 batches of 32 parallelized bool ops (160)
pub fn maj(x: &[Ciphertext; 32], y: &[Ciphertext; 32], z: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let t1 = and(x, y, sk);
    let t2 = and(x, z, sk);
    let t3 = and(y, z, sk);
    xor(&xor(&t1, &t2, sk), &t3, sk)
}

// 32 parallelized bool ops
// Building block for most of the previous functions
fn xor(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = trivial_bools(&[false; 32], sk);
    let mut handles = vec![];

    let a = Arc::new(a.clone());
    let b = Arc::new(b.clone());
    let sk = Arc::new(sk.clone());

    for t in 0..8 {
        let a = Arc::clone(&a);
        let b = Arc::clone(&b);
        let sk = Arc::clone(&sk);

        let handle = thread::spawn(move || {
            let mut partial_result = vec![
                sk.trivial_encrypt(false), sk.trivial_encrypt(false),
                sk.trivial_encrypt(false), sk.trivial_encrypt(false),
            ];

            let start = t * 4;
            let end = start + 4;

            for i in start..end {
                let idx = i - start;
                partial_result[idx] = sk.xor(&a[i], &b[i]);
            }
            partial_result
        });

        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        let partial_result = handle.join().unwrap();
        let start = i * 4;
        let end = start + 4;

        result[start..end].clone_from_slice(&partial_result);
    }
    result
}

fn and(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = trivial_bools(&[false; 32], sk);
    let mut handles = vec![];

    let a = Arc::new(a.clone());
    let b = Arc::new(b.clone());
    let sk = Arc::new(sk.clone());

    for t in 0..8 {
        let a = Arc::clone(&a);
        let b = Arc::clone(&b);
        let sk = Arc::clone(&sk);

        let handle = thread::spawn(move || {
            let mut partial_result = vec![
                sk.trivial_encrypt(false), sk.trivial_encrypt(false),
                sk.trivial_encrypt(false), sk.trivial_encrypt(false),
            ];

            let start = t * 4;
            let end = start + 4;

            for i in start..end {
                let idx = i - start;
                partial_result[idx] = sk.and(&a[i], &b[i]);
            }
            partial_result
        });

        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        let partial_result = handle.join().unwrap();
        let start = i * 4;
        let end = start + 4;

        result[start..end].clone_from_slice(&partial_result);
    }
    result
}

fn not(a: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = trivial_bools(&[false; 32], sk);
    let mut handles = vec![];

    let a = Arc::new(a.clone());
    let sk = Arc::new(sk.clone());

    for t in 0..8 {
        let a = Arc::clone(&a);
        let sk = Arc::clone(&sk);

        let handle = thread::spawn(move || {
            let mut partial_result = vec![
                sk.trivial_encrypt(false), sk.trivial_encrypt(false),
                sk.trivial_encrypt(false), sk.trivial_encrypt(false),
            ];

            let start = t * 4;
            let end = start + 4;

            for i in start..end {
                let idx = i - start;
                partial_result[idx] = sk.not(&a[i]);
            }
            partial_result
        });

        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        let partial_result = handle.join().unwrap();
        let start = i * 4;
        let end = start + 4;

        result[start..end].clone_from_slice(&partial_result);
    }
    result
}

// Trivial encryption of 32 bools
pub fn trivial_bools(bools: &[bool; 32], sk: &ServerKey) -> [Ciphertext; 32] {

    [
        sk.trivial_encrypt(bools[0]), sk.trivial_encrypt(bools[1]), sk.trivial_encrypt(bools[2]), sk.trivial_encrypt(bools[3]),
        sk.trivial_encrypt(bools[4]), sk.trivial_encrypt(bools[5]), sk.trivial_encrypt(bools[6]), sk.trivial_encrypt(bools[7]),
        sk.trivial_encrypt(bools[8]), sk.trivial_encrypt(bools[9]), sk.trivial_encrypt(bools[10]), sk.trivial_encrypt(bools[11]),
        sk.trivial_encrypt(bools[12]), sk.trivial_encrypt(bools[13]), sk.trivial_encrypt(bools[14]), sk.trivial_encrypt(bools[15]),
        sk.trivial_encrypt(bools[16]), sk.trivial_encrypt(bools[17]), sk.trivial_encrypt(bools[18]), sk.trivial_encrypt(bools[19]),
        sk.trivial_encrypt(bools[20]), sk.trivial_encrypt(bools[21]), sk.trivial_encrypt(bools[22]), sk.trivial_encrypt(bools[23]),
        sk.trivial_encrypt(bools[24]), sk.trivial_encrypt(bools[25]), sk.trivial_encrypt(bools[26]), sk.trivial_encrypt(bools[27]),
        sk.trivial_encrypt(bools[28]), sk.trivial_encrypt(bools[29]), sk.trivial_encrypt(bools[30]), sk.trivial_encrypt(bools[31]),
    ]
}

#[cfg(test)]
mod tests {
    use tfhe::boolean::prelude::*;
    use super::*;

    fn to_bool_array(arr: [i32; 32]) -> [bool; 32] {
        let mut bool_arr = [false; 32];
        for i in 0..32 {
            if arr[i] == 1 {
                bool_arr[i] = true;
            }
        }
        bool_arr
    }
    fn encrypt(bools: &[bool; 32], ck: &ClientKey) -> [Ciphertext; 32] {
        [
            ck.encrypt(bools[0]), ck.encrypt(bools[1]), ck.encrypt(bools[2]), ck.encrypt(bools[3]),
            ck.encrypt(bools[4]), ck.encrypt(bools[5]), ck.encrypt(bools[6]), ck.encrypt(bools[7]),
            ck.encrypt(bools[8]), ck.encrypt(bools[9]), ck.encrypt(bools[10]), ck.encrypt(bools[11]),
            ck.encrypt(bools[12]), ck.encrypt(bools[13]), ck.encrypt(bools[14]), ck.encrypt(bools[15]),
            ck.encrypt(bools[16]), ck.encrypt(bools[17]), ck.encrypt(bools[18]), ck.encrypt(bools[19]),
            ck.encrypt(bools[20]), ck.encrypt(bools[21]), ck.encrypt(bools[22]), ck.encrypt(bools[23]),
            ck.encrypt(bools[24]), ck.encrypt(bools[25]), ck.encrypt(bools[26]), ck.encrypt(bools[27]),
            ck.encrypt(bools[28]), ck.encrypt(bools[29]), ck.encrypt(bools[30]), ck.encrypt(bools[31]),
        ]
    }
    fn decrypt(bools: &[Ciphertext; 32], ck: &ClientKey) -> [bool; 32] {
        [
            ck.decrypt(&bools[0]), ck.decrypt(&bools[1]), ck.decrypt(&bools[2]), ck.decrypt(&bools[3]),
            ck.decrypt(&bools[4]), ck.decrypt(&bools[5]), ck.decrypt(&bools[6]), ck.decrypt(&bools[7]),
            ck.decrypt(&bools[8]), ck.decrypt(&bools[9]), ck.decrypt(&bools[10]), ck.decrypt(&bools[11]),
            ck.decrypt(&bools[12]), ck.decrypt(&bools[13]), ck.decrypt(&bools[14]), ck.decrypt(&bools[15]),
            ck.decrypt(&bools[16]), ck.decrypt(&bools[17]), ck.decrypt(&bools[18]), ck.decrypt(&bools[19]),
            ck.decrypt(&bools[20]), ck.decrypt(&bools[21]), ck.decrypt(&bools[22]), ck.decrypt(&bools[23]),
            ck.decrypt(&bools[24]), ck.decrypt(&bools[25]), ck.decrypt(&bools[26]), ck.decrypt(&bools[27]),
            ck.decrypt(&bools[28]), ck.decrypt(&bools[29]), ck.decrypt(&bools[30]), ck.decrypt(&bools[31]),
        ]
    }


    #[test]
    fn test_add_modulo_2_32() {
        let (ck, sk) = gen_keys();

        let a = encrypt(&to_bool_array([0,1,0,1,1,0,1,1,1,1,1,0,0,0,0,0,1,1,0,0,1,1,0,1,0,0,0,1,1,0,0,1,]), &ck);
        let b = encrypt(&to_bool_array([0,0,1,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,0,0,1,1,1,0,0,1,0,1,0,1,1,]), &ck);
        let c = encrypt(&to_bool_array([0,0,0,1,1,1,1,1,1,0,0,0,0,1,0,1,1,1,0,0,1,0,0,1,1,0,0,0,1,1,0,0,]), &ck);
        let d = encrypt(&to_bool_array([0,1,0,0,0,0,1,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,1,1,1,0,0,1,1,0,0,0,]), &ck);
        let e = encrypt(&to_bool_array([0,1,1,0,1,0,0,0,0,1,1,0,0,1,0,1,0,1,1,0,1,1,0,0,0,1,1,0,1,1,0,0,]), &ck);

        let output = add(&add(&add(&a, &b, &sk), &add(&c, &d, &sk), &sk), &e, &sk);
        let result = decrypt(&output, &ck);
        let expected = to_bool_array([0,1,0,1,1,0,1,1,1,1,0,1,1,1,0,1,0,1,0,1,1,0,0,1,1,1,0,1,0,1,0,0,]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_sigma0() {
        let (ck, sk) = gen_keys();

        let input = encrypt(&to_bool_array([0,1,1,0,1,1,1,1,0,0,1,0,0,0,0,0,0,1,1,1,0,1,1,1,0,1,1,0,1,1,1,1,]), &ck);
        let output = sigma0(&input, &sk);
        let result = decrypt(&output, &ck);
        let expected = to_bool_array([1,1,0,0,1,1,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,0,1,1,]);

        assert_eq!(result, expected);
    } //the other sigmas are implemented in the same way

    #[test]
    fn test_ch() {
    let (ck, sk) = gen_keys();

    let e = encrypt(&to_bool_array([0,1,0,1,0,0,0,1,0,0,0,0,1,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,1,1,1,1,]), &ck);
    let f = encrypt(&to_bool_array([1,0,0,1,1,0,1,1,0,0,0,0,0,1,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,1,0,0,]), &ck);
    let g = encrypt(&to_bool_array([0,0,0,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1,0,1,1,0,0,1,1,0,1,0,1,0,1,1,]), &ck);

    let output = ch(&e, &f, &g, &sk);
    let result = decrypt(&output, &ck);
    let expected = to_bool_array([0,0,0,1,1,1,1,1,1,0,0,0,0,1,0,1,1,1,0,0,1,0,0,1,1,0,0,0,1,1,0,0,]);

    assert_eq!(result, expected);
}

    #[test]
    fn test_maj() {
        let (ck, sk) = gen_keys();

        let a = encrypt(&to_bool_array([0,1,1,0,1,0,1,0,0,0,0,0,1,0,0,1,1,1,1,0,0,1,1,0,0,1,1,0,0,1,1,1,]), &ck);
        let b = encrypt(&to_bool_array([1,0,1,1,1,0,1,1,0,1,1,0,0,1,1,1,1,0,1,0,1,1,1,0,1,0,0,0,0,1,0,1,]), &ck);
        let c = encrypt(&to_bool_array([0,0,1,1,1,1,0,0,0,1,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,0,]), &ck);

        let output = maj(&a, &b, &c, &sk);
        let result = decrypt(&output, &ck);
        let expected = to_bool_array([0,0,1,1,1,0,1,0,0,1,1,0,1,1,1,1,1,1,1,0,0,1,1,0,0,1,1,0,0,1,1,1,]);

        assert_eq!(result, expected);
    }
}