mod crx_file {
    // output file name is protobuf package name
    include!(concat!(env!("OUT_DIR"), "/crx_file.rs"));
}

pub use crx_file::*;

use prost::Message;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::signature::SignatureEncoding;
use rsa::signature::Verifier;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

const CRX3_MAGIC: &[u8; 4] = b"Cr24";
const CRX3_VERSION: u32 = 3;

pub struct Crx3Builder {
    private_key: RsaPrivateKey,
    zip_data: Vec<u8>,
}

pub struct Crx3File {
    header: CrxFileHeader,
    zip_data: Vec<u8>,
}

impl Crx3Builder {
    pub fn new(private_key: RsaPrivateKey, zip_data: Vec<u8>) -> Self {
        Self {
            private_key,
            zip_data,
        }
    }

    pub fn from_zip_path<P: AsRef<Path>>(
        private_key: RsaPrivateKey,
        zip_path: P,
    ) -> io::Result<Self> {
        let zip_data = fs::read(zip_path)?;
        Ok(Self::new(private_key, zip_data))
    }

    pub fn build(self) -> io::Result<Crx3File> {
        // Generate public key
        let public_key = self.private_key.to_public_key();
        let public_key_der = public_key.to_public_key_der().unwrap();

        // Create signed data (CRX ID is derived from public key)
        let crx_id = get_crx_id(public_key_der.as_bytes())?;
        let signed_data = SignedData {
            crx_id: Some(crx_id),
        };

        // Encode signed_data
        let mut signed_header_data = Vec::new();
        signed_data.encode(&mut signed_header_data)?;

        // Prepare data to sign
        let signed_header_size = signed_header_data.len() as u32;
        let mut data_to_sign = b"CRX3 SignedData\x00".to_vec();
        data_to_sign.extend_from_slice(&signed_header_size.to_le_bytes());
        data_to_sign.extend_from_slice(&signed_header_data);
        data_to_sign.extend_from_slice(&self.zip_data);

        // Create signature
        let signature = sign_data(&self.private_key, &data_to_sign)?;

        // Build CRX3 header
        let header = CrxFileHeader {
            sha256_with_rsa: vec![AsymmetricKeyProof {
                public_key: Some(public_key_der.as_bytes().to_vec()),
                signature: Some(signature),
            }],
            sha256_with_ecdsa: vec![],
            signed_header_data: Some(signed_header_data),
        };

        Ok(Crx3File {
            header,
            zip_data: self.zip_data,
        })
    }
}

impl Crx3File {
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = fs::File::open(path)?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;

        if magic != *CRX3_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Not a valid CRX3 file (invalid magic)",
            ));
        }

        let mut version = [0u8; 4];
        file.read_exact(&mut version)?;
        let version = u32::from_le_bytes(version);

        if version != CRX3_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported CRX version: {}", version),
            ));
        }

        let mut header_size = [0u8; 4];
        file.read_exact(&mut header_size)?;
        let header_size = u32::from_le_bytes(header_size);

        let mut header_data = vec![0u8; header_size as usize];
        file.read_exact(&mut header_data)?;

        let header = CrxFileHeader::decode(&header_data[..])?;

        let mut zip_data = Vec::new();
        file.read_to_end(&mut zip_data)?;

        Ok(Self { header, zip_data })
    }

    pub fn verify(&self) -> io::Result<bool> {
        if self.header.sha256_with_rsa.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "No RSA signature found",
            ));
        }

        let proof = &self.header.sha256_with_rsa[0];
        let public_key_data = match &proof.public_key {
            Some(data) => data,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "No public key found",
                ));
            }
        };

        let signature = match &proof.signature {
            Some(data) => data,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "No signature found",
                ));
            }
        };

        let signed_header_data = match &self.header.signed_header_data {
            Some(data) => data,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "No signed header data found",
                ));
            }
        };

        // Recreate data that was signed
        let signed_header_size = signed_header_data.len() as u32;
        let mut data_to_verify = b"CRX3 SignedData\x00".to_vec();
        data_to_verify.extend_from_slice(&signed_header_size.to_le_bytes());
        data_to_verify.extend_from_slice(signed_header_data);
        data_to_verify.extend_from_slice(&self.zip_data);

        // Verify signature
        let public_key = match RsaPublicKey::from_public_key_der(public_key_data) {
            Ok(key) => key,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse public key: {}", e),
                ));
            }
        };

        verify_signature(&public_key, &data_to_verify, signature)
    }

    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = fs::File::create(path)?;

        // Write magic number
        file.write_all(CRX3_MAGIC)?;

        // Write version
        file.write_all(&CRX3_VERSION.to_le_bytes())?;

        // Encode header
        let mut header_data = Vec::new();
        self.header.encode(&mut header_data)?;

        // Write header size and data
        file.write_all(&(header_data.len() as u32).to_le_bytes())?;
        file.write_all(&header_data)?;

        // Write ZIP data
        file.write_all(&self.zip_data)?;

        Ok(())
    }

    pub fn extract_zip<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        fs::write(path, &self.zip_data)
    }

    pub fn get_crx_id(&self) -> io::Result<Vec<u8>> {
        if let Some(signed_header_data) = &self.header.signed_header_data {
            let signed_data = SignedData::decode(&signed_header_data[..])?;

            if let Some(crx_id) = signed_data.crx_id {
                return Ok(crx_id);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No CRX ID found",
        ))
    }
}

// Helper functions

fn get_crx_id(public_key_data: &[u8]) -> io::Result<Vec<u8>> {
    // In Chrome extensions, the extension ID is derived from the SHA-256 hash of the
    // SubjectPublicKeyInfo representation of the public key
    use rsa::sha2::{Digest, Sha256};

    // The public_key_data is already in DER encoded SPKI format (SubjectPublicKeyInfo)
    // which is what Chrome uses to calculate the extension ID
    let mut hasher = Sha256::new();
    hasher.update(public_key_data);
    let hash = hasher.finalize();

    // Take first 16 bytes
    Ok(hash[..16].to_vec())
}

// Formats a raw extension ID (16 bytes) to the Chrome extension ID format
pub fn format_extension_id(raw_id: &[u8]) -> String {
    // Chrome uses base26 (a-z) encoding with an offset of 10 (0->a, 9->j, 15->p)
    // Reference: golang implementation of Chrome extension ID format

    // First convert each byte to 2 hex characters
    let hex_string = raw_id
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Then convert each hex character to the Chrome extension ID format
    hex_string
        .chars()
        .map(|c| {
            // Parse the hex character into a number (0-15)
            let n = c.to_digit(16).unwrap_or(0);

            // Convert to a base26 character with offset 10 (a-p range for 0-15)
            let char_code = (n + 10) as u8 + b'a' - 10;
            char_code as char
        })
        .collect()
}

fn sign_data(private_key: &RsaPrivateKey, data: &[u8]) -> io::Result<Vec<u8>> {
    // For simplicity, using PSS scheme directly
    use rsa::pss::SigningKey;
    use rsa::sha2::Sha256;
    use rsa::signature::RandomizedSigner;

    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let signature = signing_key.sign_with_rng(&mut rand::thread_rng(), data);

    Ok(signature.to_vec())
}

fn verify_signature(public_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> io::Result<bool> {
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::sha2::Sha256;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());

    // Convert the byte slice to a Signature
    let sig = match Signature::try_from(signature) {
        Ok(s) => s,
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to convert signature: {}", e),
            ));
        }
    };

    match verifying_key.verify(data, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    // Helper function to generate a test RSA key
    fn generate_test_key() -> RsaPrivateKey {
        let bits = 2048;
        RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap()
    }

    // Helper function to create a simple test ZIP file
    fn create_test_zip() -> Vec<u8> {
        // Simple minimal ZIP format data
        vec![
            0x50, 0x4B, 0x05, 0x06, // End of central directory signature
            0x00, 0x00, 0x00, 0x00, // Disk numbers
            0x00, 0x00, 0x00, 0x00, // Central directory entries
            0x00, 0x00, 0x00, 0x00, // Central directory size
            0x00, 0x00, 0x00, 0x00, // Central directory offset
            0x00, 0x00, // Comment length
        ]
    }

    #[test]
    fn test_crx3_roundtrip() {
        // Generate a test key
        let private_key = generate_test_key();

        // Create a test ZIP
        let zip_data = create_test_zip();

        // Build a CRX file
        let builder = Crx3Builder::new(private_key, zip_data.clone());
        let crx = builder.build().unwrap();

        // Create a temporary file
        let tmp_dir = env::temp_dir();
        let crx_path = tmp_dir.join("test.crx");

        // Write the CRX to a file
        crx.write_to_file(&crx_path).unwrap();

        // Read it back
        let loaded_crx = Crx3File::from_file(&crx_path).unwrap();

        // Verify it
        assert!(loaded_crx.verify().unwrap());

        // Extract ZIP and verify it matches the original
        let zip_path = tmp_dir.join("test.zip");
        loaded_crx.extract_zip(&zip_path).unwrap();

        let extracted_zip = fs::read(&zip_path).unwrap();
        assert_eq!(extracted_zip, zip_data);

        // Clean up
        fs::remove_file(crx_path).unwrap();
        fs::remove_file(zip_path).unwrap();
    }

    #[test]
    fn test_crx_id_generation() {
        // Generate a test key
        let private_key = generate_test_key();
        let public_key = private_key.to_public_key();
        let public_key_der = public_key.to_public_key_der().unwrap();

        // Generate CRX ID
        let crx_id = get_crx_id(public_key_der.as_bytes()).unwrap();

        // Make sure it's the correct length (16 bytes)
        assert_eq!(crx_id.len(), 16);
    }

    #[test]
    fn test_extension_id_format() {
        // Test with a known byte array
        let test_bytes = [
            0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7,
            0xe8, 0xf9,
        ];

        // Format as Chrome extension ID
        let extension_id = format_extension_id(&test_bytes);

        // The extension ID should be 32 characters long (each byte becomes 2 characters)
        assert_eq!(extension_id.len(), 32);

        // Expected result: each byte produces 2 hex chars, then each is mapped to a-p
        // 0->a, 1->b, ..., 9->j, a->k, b->l, ... f->p
        let expected = "akblcmdneofpgahbicjdkelfmgnhoipj";
        assert_eq!(extension_id, expected);

        // Verify all characters are in a-p range (base16 + offset 10 -> a-p)
        for c in extension_id.chars() {
            assert!(c >= 'a' && c <= 'p');
        }
    }

    #[test]
    fn test_extension_id_format_file() {
        let crx = Crx3File::from_file("testdata/chrome-extension.crx").unwrap();
        let crx_id = crx.get_crx_id().unwrap();
        let appid = format_extension_id(&crx_id);

        assert_eq!(appid, "cdofnkkjddjieacnedgfcbndilidfihj");
    }
}
