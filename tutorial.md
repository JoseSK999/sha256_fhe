# Tutorial

## Intro

In this tutorial we will go through the steps to turn a regular sha256 implementation into its homomorphic version. We will explain the basics of the sha256 function first, and then how to implement it homomorphically with performance considerations. Finally we will discuss design choices and further improvements yet to be made.

## Sha256

The first step in this experiment is actually implementing the sha256 function. We can find the specification [here](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf), but let's summarize the three main sections of the document.

#### Padding

The sha256 function processes the input data in blocks or chunks of 512 bits. Before actually performing the hash computations we have to pad the input in the following way:
* Append a single "1" bit
* Append a number of "0" bits such that exactly 64 bits are left to make the message length a multiple of 512
* Append the last 64 bits as a binary encoding of the original input length

Or visually:

```
0                                   L   L+1                              L+1+k                  L+1+k+64
|-----------------------------------|---|--------------------------------|----------------------|
    Original input (L bits)        "1" bit          "0" bits             Encoding of the number L
```
Where the numbers on the top represent the length of the padded input at each position, and L+1+k+64 is a multiple of 512 (the length of the padded input).

#### Operations and functions

We also find the operations that we will use as building blocks for functions inside the sha256 computation. These are bitwise AND, XOR, NOT, addition modulo 2^32 and the Rotate Right (ROTR) and Shift Right (SHR) operations, all working with 32-bit words and producing a new word.

Note that ROTR and SHR can be evaluated by changing the index of each individual bit of the word, even if each bit is encrypted. Note also that the other bitwise operations can be computed homomorphically and that addition can be broken down into homomorphic boolean operations.

We then combine the operations inside the sigma (with 4 variations), ch and maj functions. At the end of the day, when we change the sha256 to be computed homomorphically, we will mainly change the isolated code of the operations used within these functions.

Here is the definition of each function:
```
Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z)
Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)

Σ0(x) = ROTR-2(x) XOR ROTR-13(x) XOR ROTR-22(x)
Σ1(x) = ROTR-6(x) XOR ROTR-11(x) XOR ROTR-25(x)
σ0(x) = ROTR-7(x) XOR ROTR-18(x) XOR SHR-3(x)
σ1(x) = ROTR-17(x) XOR ROTR-19(x) XOR SHR-10(x)
```

#### Sha256 computation

As we have mentioned, the sha256 function works with chunks of 512 bits. For each chunk, we will compute 64 32-bit words. 16 will come from the 512 bits and the rest will be computed using the previous functions. After computing the 64 words, and still within the same chunk iteration, a compression loop will compute a hash value (8 32-bit words), again using the previous functions and some constants to mix everything up. When we finish the last chunk iteration, the resulting hash values will be the output of the sha256 function. 

Here is how this function looks like using arrays of 32 bools to represent words:

```rust
fn sha256(padded_input: Vec<bool>) -> [bool; 256] {

    // Initialize hash values with constant values
    let mut hash: [[bool; 32]; 8] = [
        hex_to_bools(0x6a09e667), hex_to_bools(0xbb67ae85),
        hex_to_bools(0x3c6ef372), hex_to_bools(0xa54ff53a),
        hex_to_bools(0x510e527f), hex_to_bools(0x9b05688c),
        hex_to_bools(0x1f83d9ab), hex_to_bools(0x5be0cd19),
    ];

    let chunks = padded_input.chunks(512);

    for chunk in chunks {
        let mut w = [[false; 32]; 64];

        // Copy first 16 words from current chunk
        for i in 0..16 {
            w[i].copy_from_slice(&chunk[i * 32..(i + 1) * 32]);
        }

        // Compute the other 48 words
        for i in 16..64 {
            w[i] = add(add(add(sigma1(&w[i - 2]), w[i - 7]), sigma0(&w[i - 15])), w[i - 16]);
        }

        let mut a = hash[0];
        let mut b = hash[1];
        let mut c = hash[2];
        let mut d = hash[3];
        let mut e = hash[4];
        let mut f = hash[5];
        let mut g = hash[6];
        let mut h = hash[7];

        // Compression loop, each iteration uses a specific constant from K
        for i in 0..64 {
            let temp1 = add(add(add(add(h, ch(&e, &f, &g)), w[i]), hex_to_bools(K[i])), sigma_upper_case_1(&e));
            let temp2 = add(sigma_upper_case_0(&a), maj(&a, &b, &c));
            h = g;
            g = f;
            f = e;
            e = add(d, temp1);
            d = c;
            c = b;
            b = a;
            a = add(temp1, temp2);
        }

        hash[0] = add(hash[0], a);
        hash[1] = add(hash[1], b);
        hash[2] = add(hash[2], c);
        hash[3] = add(hash[3], d);
        hash[4] = add(hash[4], e);
        hash[5] = add(hash[5], f);
        hash[6] = add(hash[6], g);
        hash[7] = add(hash[7], h);
    }

    // Concatenate the final hash values to produce a 256-bit hash
    let mut output = [false; 256];
    for i in 0..8 {
        output[i * 32..(i + 1) * 32].copy_from_slice(&hash[i]);
    }
    output
}
```

## Making it homomorphic

The key idea here is that we can replace each bit of the input data with a Fully Homomorphic Encryption of the same bit value, and operate over the encrypted values using homomorphic operations. To achieve this we need to change the function signatures and deal with the borrowing rules of the Ciphertext type, which represents an encrypted bit, but the structure of the sha256 function remains the same. The part of the code that requires more consideration is the implementation of the sha256 operations, since they will use homomorphic boolean operations internally.

Since the homomorphic boolean operations are really expensive, we have to remove unnecessary homomorphic operations and maximize parallelization such that we can use multithreading to speed up the computation. Let's take a look at each sha256 operation.

#### Rotate Right and Shift Right

As we have highlighted, these two operations can be evaluated by changing the position of each encrypted bit in the word, thereby requiring 0 homomorphic operations. Here is our implementation:

```rust
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
```
We see a function called ``trivial_bools`` that we will use along our implementation to initialize an array of 32 Ciphertexts. This is because we cannot copy the same Ciphertext for each position of the array as we do with simple bools, so we create 32 different trivial encryptions. We will also use this function in order to trivially encrypt constant values to operate homomorphically with them.

#### Bitwise XOR, AND, NOT

To implement these operations we will use the ```xor```, ```and``` and ```not``` methods provided by the tfhe library to evaluate each boolean operation homomorphically. It's important to note that, since we will operate bitwise, we can parallelize the homomorphic computations. In other words, we can homomorphically XOR the bits at index 0 of two words using a thread, while XORing the bits at index 1 using another thread, and so on. This means we could compute these bitwise operations using up to 32 concurrent threads (since we work with 32-bit words).

In our specific implementation we have used 8 threads, which modern computers usually support. However we can change the parameters as we will soon demonstrate to change the number of threads, or even replace them with more advanced concurrency techniques.

Here is our implementation of the bitwise homomorphic XOR operation, where each thread computes a partial result of 4 bits (8 threads * 4 bits = 32 bits). When all the partial results have been computed we combine them into the resulting 32 Ciphertext array. The other two bitwise operations are implemented in the same way.

```rust
fn xor(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = trivial_bools(&[false; 32], sk);
    let mut handles = vec![];

    let a = Arc::new(a.clone());
    let b = Arc::new(b.clone());
    let sk = Arc::new(sk.clone());

    for t in 0..8 { // 8 threads
        let a = Arc::clone(&a);
        let b = Arc::clone(&b);
        let sk = Arc::clone(&sk);

        let handle = thread::spawn(move || {
            let mut partial_result = vec![
                sk.trivial_encrypt(false), sk.trivial_encrypt(false),
                sk.trivial_encrypt(false), sk.trivial_encrypt(false), // Length of partial result = 4
            ];

            let start = t * 4;
            let end = start + 4;

            for i in start..end {
                let idx = i - start;
                partial_result[idx] = sk.xor(&a[i], &b[i]); // homomorphic boolean XOR
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
```
Note that ```partial_result``` is initialized with 4 Ciphertexts and that we compute ```start``` multiplying a variable by 4 and ```end``` by adding 4. So if for instance we want to use 16 threads, we will have to run the first for loop 16 times, set the length of ```partial_result``` to 2 (16 * 2 = 32) and also compute ```start``` and ```end``` using 2. And that's it.

#### Addition modulo 2^32

This is perhaps the trickiest operation to efficiently implement in a homomorphic fashion. A naive implementation could use the Ripple Carry Adder algorithm, which is straightforward but cannot be parallelized because each step depends on the previous one.

A better choice would be the Carry Lookahead Adder, which allows us to use the previous AND and XOR bitwise operations. This way we are abstracting away the parallel processing of the addition operation. Here is our implementation, which is around 50% faster than the naive Ripple Carry Adder.

```rust
pub fn add(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let propagate = xor(a, b, sk); // Parallelized bitwise XOR
    let generate = and(a, b, sk); // Parallelized bitwise AND

    let carry = compute_carry(&propagate, &generate, sk);
    let sum = xor(&propagate, &carry, sk); // Parallelized bitwise XOR

    sum
}
```

With all these sha256 operations working homomorphically, our functions will be homomomorphic as well and the whole sha256 function too (after adapting the code to work with the Ciphertext type).

## Usage of sha256_fhe

So far we have only looked at each part of our homomorphic implementation, but how does it work at a high level? The usage of sha256_fhe would look like this:

KEY GENERATION
* Client generates his private key (client key) and the server key.

PADDING AND ENCRYPTION
* Client pads the data he wants to compute the sha256 on.
* Client encrypts each bit of the padded data with his private key.
* Client sends the server key and the encrypted padded data to the server.

HOMOMORPHIC COMPUTATION
* Server computes the homomorphic sha256 function.
* Server sends the output to the client.

DECRYPTION
* Finally client decrypts each bit of the output to get the hash value.

We can see that the padding part is executed on the client side. In this way the server will not even learn the exact size of the input data. Another option would be to implement the padding function to receive the encrypted data and pad it with trivial encryptions.
