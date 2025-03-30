# crx3-rs

A Rust library and command-line tool for handling Chrome extension CRX3 format.

## Features

- Parse Chrome extension CRX3 format
- Create CRX3 format Chrome extensions from ZIP files
- Verify signatures of CRX3 format Chrome extensions
- Extract ZIP files from CRX3 files
- Get Extension ID (CRX ID) from CRX3 files

## Installation

```
cargo install crx3-rs
```

Or clone the repository and build:

```
git clone https://github.com/yourusername/crx3-rs.git
cd crx3-rs
cargo build --release
```

## Usage

### Command-line Tool

```
# Convert Chrome extension ZIP to CRX3 format
crx3-rs create extension.zip private_key.pem extension.crx

# Verify signature of CRX3 file
crx3-rs verify extension.crx

# Extract ZIP from CRX3 file
crx3-rs extract extension.crx extracted.zip
```

### Library Usage

```rust
use std::fs;

use crx3_rs::{Crx3Builder, Crx3File};
use rsa::pkcs8::DecodePrivateKey;

// Load private key
let private_key_data = fs::read_to_string("private_key.pem").unwrap();
let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(&private_key_data).unwrap();

// Create CRX3 from ZIP data
let builder = Crx3Builder::from_zip_path(private_key, "extension.zip").unwrap();
let crx = builder.build().unwrap();

// Write CRX3 to file
crx.write_to_file("extension.crx").unwrap();

// Load and verify CRX3 file
let crx = Crx3File::from_file("extension.crx").unwrap();
if crx.verify().unwrap() {
    println!("Signature verification successful!");
    
    // Get Extension ID (CRX ID)
    let crx_id = crx.get_crx_id().unwrap();
    let crx_id_hex = crx_id.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("");
    println!("Extension ID: {}", crx_id_hex);
} else {
    println!("Signature verification failed");
}
```

## Generating Private Keys

To generate a private key for testing purposes, use the following OpenSSL command:

```
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```

## License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

## References

- [Chrome Extension Protobuf](https://raw.githubusercontent.com/chromium/chromium/main/components/crx_file/crx3.proto)
