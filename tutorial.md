# Tutorial

## Intro

In this tutorial we will go through the steps to turn a regular sha256 implementation into its homomorphic version. We will explain the basics of the sha256 function first, and then the changes we made to it, including optimizations. Finally we will discuss further improvements yet to be made.

## Sha256

The first step in this experiment is actually implementing the sha256 function. We can find the specification [here](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf), but let's dissect the three main parts that we find in the document.

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

We also find the operations that we will be using as building blocks for functions inside the sha256 computation. These are bitwise AND, XOR, NOT, addition modulo 2^32 and the Rotate Right (ROTR) and Right Shift (SHR) operations, all working with 32-bit words.

Note that ROTR and SHR can be evaluated by changing the index of each individual bit of the word, even if each bit is encrypted. Note also that the other bitwise operations can be computed homomorphically and that addition can be broken down into homomorphic bitwise operations.

We then combine the operations inside the sigma (with 4 variations), ch and maj functions. At the end of the day, when we change the sha256 to be computed homomorphically, we will mainly change the isolated code of the operations used within these functions.

#### Sha256 computation

As we have mentioned, the sha256 function works with chunks of 512 bits. For each chunk, we will compute 64 32-bit words. 16 will come from the 512 bits and the rest will be computed using the previous functions. After computing the 64 words, and still within the same chunk iteration, a compression loop will compute a hash value (8 32-bit words), again using the previous functions and some constants to mix everything up. When we finish the last chunk iteration, the resulting hash values will be the output of the sha256 function. 

Here is how this function looks like using arrays of 32 bools to represent words:

```rust
fn sha256(padded_input: Vec<bool>) -> [bool; 256] {

    // Initialize hash values
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

        // Compression loop
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