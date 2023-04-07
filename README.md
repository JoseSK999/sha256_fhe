# sha256_fhe

This repo contains the implementation of a homomorphic sha256 function. In other words, a function that computes a sha256 hash over encrypted data such that H(E(Data)) = E(H(Data)).

Make sure to add the correct dependency to the Cargo.toml file depending on your computer architecture:
```
tfhe = { version = "0.1.12", features = ["boolean", "x86_64-unix"] }
```
```
tfhe = { version = "0.1.12", features = ["boolean", "aarch64-unix"] }
```
