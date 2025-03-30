# crx3-rs

A Rust library and command-line tool for handling Chrome extension CRX3 format.

## Features

- Parse Chrome extension CRX3 format
- Create CRX3 format Chrome extensions from ZIP files
- Verify signatures of CRX3 format Chrome extensions
- Extract ZIP files from CRX3 files
- Get Extension ID (CRX ID) from CRX3 files
- Format extension IDs in Chrome's standard format
- Stream-based API with Reader/Writer support
- Memory-efficient operations for in-memory processing

## Installation

### From source

```
cargo install crx3-rs
```

### Using cargo-binstall (Faster)

For a faster installation without compilation, you can use cargo-binstall:

```
# Install cargo-binstall (if you don't have it)
cargo install cargo-binstall

# Install crx3-rs
cargo binstall crx3-rs
```

### From repository

```
git clone https://github.com/imishinist/crx3-rs.git
cd crx3-rs
cargo build --release
```

## Usage

### Command-line Tool

```
# Convert Chrome extension ZIP to CRX3 format
crx3rs create extension.zip private_key.pem extension.crx

# Verify signature of CRX3 file
crx3rs verify extension.crx

# Extract ZIP from CRX3 file
crx3rs extract extension.crx extracted.zip

# Get Chrome extension ID from CRX3 file
crx3rs id extension.crx
```

### Library Usage

#### Creating a CRX3 file

```rust
use std::fs;
use crx3_rs::Crx3Builder;
use rsa::pkcs8::DecodePrivateKey;

// Load private key from PEM file
let private_key_data = fs::read_to_string("private_key.pem").unwrap();
let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(&private_key_data).unwrap();

// From a ZIP file
let crx = Crx3Builder::from_zip_path(private_key, "extension.zip").unwrap()
    .build().unwrap();

// Or from in-memory ZIP data
let zip_data = fs::read("extension.zip").unwrap();
let crx = Crx3Builder::new(private_key, zip_data)
    .build().unwrap();

// Or from a reader (any type that implements Read)
let file = fs::File::open("extension.zip").unwrap();
let crx = Crx3Builder::from_reader(private_key, file).unwrap()
    .build().unwrap();

// Write to a file
crx.write_to_file("extension.crx").unwrap();

// Or get as bytes
let crx_bytes = crx.to_bytes().unwrap();

// Or write to any type that implements Write
let mut file = fs::File::create("extension.crx").unwrap();
crx.write_to(&mut file).unwrap();
```

#### Reading a CRX3 file

```rust
use crx3_rs::{Crx3File, format_extension_id};
use std::io::Read;

// From a file
let crx = Crx3File::from_file("extension.crx").unwrap();

// Or from bytes
let data = std::fs::read("extension.crx").unwrap();
let crx = Crx3File::from_bytes(&data).unwrap();

// Or from a reader (any type that implements Read)
let mut file = std::fs::File::open("extension.crx").unwrap();
let crx = Crx3File::from_reader(file).unwrap();

// Verify the signature
if let Ok(_) = crx.verify() {
    println!("Signature verification successful!");
    
    // Get Extension ID (CRX ID) in raw binary format
    let raw_id = crx.get_crx_id().unwrap();
    
    // Format it to Chrome's standard format (a-p characters)
    let formatted_id = format_extension_id(&raw_id);
    println!("Extension ID: {}", formatted_id);
    
    // Extract the ZIP content to a file
    crx.extract_zip("extracted.zip").unwrap();
    
    // Or access the ZIP content directly as bytes
    let zip_bytes = crx.get_zip_content();
    println!("ZIP size: {} bytes", zip_bytes.len());
}
```

## Generating Private Keys

To generate a private key for testing purposes, use the following OpenSSL command:

```
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```

## Error Handling

The library provides a comprehensive error system via the `Error` enum that wraps all possible error types that may occur during CRX3 operations:

```rust
use crx3_rs::{Crx3File, Error};

let result = Crx3File::from_file("extension.crx");

match result {
    Ok(crx) => {
        // Use the CRX...
    },
    Err(e) => match e {
        Error::Io(io_err) => println!("I/O error: {}", io_err),
        Error::InvalidFormat(msg) => println!("Invalid CRX format: {}", msg),
        Error::SignatureVerification => println!("Signature verification failed"),
        Error::NoSignature => println!("No RSA signature found"),
        // Handle other error types...
        _ => println!("Other error: {}", e),
    },
}
```

## License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

## References

- [Chrome Extension Protobuf](https://raw.githubusercontent.com/chromium/chromium/main/components/crx_file/crx3.proto)

## TODO

- [ ] cargo-binstall support
