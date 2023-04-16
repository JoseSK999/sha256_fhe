# sha256_fhe

This repo contains the implementation of a homomorphic sha256 function. In other words, a function that computes a sha256 hash over encrypted data such that H(E(Data)) = E(H(Data)). Hence the server that does the computation doesn't know at all the input data nor the resulting hash.

This program should be run with ```cargo run --release```.

Make sure to add the correct dependency to the Cargo.toml file depending on your computer architecture:
```
tfhe = { version = "0.1.12", features = ["boolean", "x86_64-unix"] }
```
```
tfhe = { version = "0.1.12", features = ["boolean", "aarch64-unix"] }
```
For a detailed explanation of our homomorphic sha256 implementation you can read this [tutorial](https://github.com/JoseSK999/sha256_fhe/blob/main/tutorial.md).
