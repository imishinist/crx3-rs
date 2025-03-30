mod crx_file {
    // output file name is protobuf package name
    include!(concat!(env!("OUT_DIR"), "/crx_file.rs"));
}

pub use crx_file::*;

use prost::Message;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use std::error::Error as StdError;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

/// Error types for CRX3 operations.
///
/// This enum represents all possible errors that can occur when working with
/// Chrome Extension (CRX3) files, including both internal errors and errors
/// from external dependencies.
#[derive(Debug)]
pub enum Error {
    /// I/O error from the standard library.
    ///
    /// Occurs during file operations like reading, writing, or seeking.
    Io(io::Error),

    /// Error during protobuf message encoding.
    ///
    /// Occurs when the library attempts to encode a protobuf message
    /// (e.g., during CRX file creation).
    Protobuf(prost::EncodeError),

    /// Error during protobuf message decoding.
    ///
    /// Occurs when the library attempts to decode a protobuf message
    /// (e.g., when reading a CRX header).
    ProtobufDecode(prost::DecodeError),

    /// Error during RSA cryptographic operations.
    ///
    /// Wraps the underlying RSA library's error and preserves error context.
    /// May occur during signing or verification operations.
    Rsa(rsa::Error),

    /// Error related to PKCS#8 encoding or decoding.
    ///
    /// Occurs when handling PKCS#8 formatted keys.
    Pkcs8(rsa::pkcs8::Error),

    /// Error related to SubjectPublicKeyInfo (SPKI) operations.
    ///
    /// Occurs when working with public key data in SPKI format.
    Spki(rsa::pkcs8::spki::Error),

    /// Invalid CRX file format.
    ///
    /// Occurs when a file doesn't conform to the CRX3 format specification.
    /// The string provides details about the specific format violation.
    InvalidFormat(String),

    /// Signature verification failed.
    ///
    /// Occurs when the CRX file signature doesn't match the expected value.
    SignatureVerification,

    /// Multiple RSA signatures are not supported.
    ///
    /// Occurs when a CRX file contains more than one RSA signature.
    MultipleSignatures,

    /// No RSA signature found.
    ///
    /// Occurs when attempting to verify a CRX file that doesn't contain any RSA signatures.
    NoSignature,

    /// ECDSA signatures are not supported by this library.
    ///
    /// Occurs when a CRX file contains ECDSA signatures, which this library
    /// doesn't currently support.
    EcdsaNotSupported,

    /// No signed header data found.
    ///
    /// Occurs when a CRX file lacks the required signed header data.
    NoSignedHeader,

    /// No CRX ID found.
    ///
    /// Occurs when attempting to extract an extension ID from a CRX file
    /// that doesn't contain one.
    NoCrxId,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "I/O error: {}", err),
            Error::Protobuf(err) => write!(f, "Protobuf encoding error: {}", err),
            Error::ProtobufDecode(err) => write!(f, "Protobuf decoding error: {}", err),
            Error::Rsa(err) => write!(f, "RSA operation error: {}", err),
            Error::Pkcs8(err) => write!(f, "PKCS8 error: {}", err),
            Error::Spki(err) => write!(f, "PKCS8 SPKI error: {}", err),
            Error::InvalidFormat(msg) => write!(f, "Invalid CRX format: {}", msg),
            Error::SignatureVerification => write!(f, "Signature verification failed"),
            Error::MultipleSignatures => write!(f, "Multiple RSA signatures are not supported"),
            Error::NoSignature => write!(f, "No RSA signature found"),
            Error::EcdsaNotSupported => write!(f, "ECDSA signatures are not supported"),
            Error::NoSignedHeader => write!(f, "No signed header data found"),
            Error::NoCrxId => write!(f, "No CRX ID found"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            Error::Protobuf(err) => Some(err),
            Error::ProtobufDecode(err) => Some(err),
            Error::Rsa(err) => Some(err),
            Error::Pkcs8(err) => Some(err),
            Error::Spki(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<prost::EncodeError> for Error {
    fn from(err: prost::EncodeError) -> Self {
        Error::Protobuf(err)
    }
}

impl From<prost::DecodeError> for Error {
    fn from(err: prost::DecodeError) -> Self {
        Error::ProtobufDecode(err)
    }
}

impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Self {
        Error::Rsa(err)
    }
}

impl From<rsa::pkcs8::Error> for Error {
    fn from(err: rsa::pkcs8::Error) -> Self {
        Error::Pkcs8(err)
    }
}

impl From<rsa::pkcs8::spki::Error> for Error {
    fn from(err: rsa::pkcs8::spki::Error) -> Self {
        Error::Spki(err)
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Io(io_err) => io_err,
            _ => io::Error::new(io::ErrorKind::Other, err.to_string()),
        }
    }
}

/// Result type for CRX3 operations.
///
/// This is a convenience type alias for `std::result::Result` with the error type
/// fixed to [`Error`]. It's used throughout this library for all operations that
/// might fail.
pub type Result<T> = std::result::Result<T, Error>;

const CRX3_MAGIC: &[u8; 4] = b"Cr24";
const CRX3_VERSION: u32 = 3;

/// Builder for creating CRX3 files.
///
/// This struct provides a fluent interface for creating Chrome Extension (CRX3) files
/// from a ZIP archive and RSA private key.
///
/// # Examples
///
/// ```no_run
/// # use crx3_rs::{Crx3Builder, Result};
/// # use rsa::RsaPrivateKey;
/// # fn example() -> Result<()> {
/// # let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
/// // Create a CRX file from a ZIP file and private key
/// let crx = Crx3Builder::from_zip_path(private_key, "extension.zip")?
///     .build()?;
///
/// // Write the CRX file to disk
/// crx.write_to_file("extension.crx")?;
/// # Ok(())
/// # }
/// ```
pub struct Crx3Builder {
    /// The RSA private key used for signing the CRX3 file
    private_key: RsaPrivateKey,
    /// The ZIP content of the Chrome extension
    zip_data: Vec<u8>,
}

/// Represents a Chrome Extension (CRX3) file.
///
/// This struct provides methods for working with CRX3 files, including verification,
/// writing to disk, and extracting the ZIP contents.
///
/// # Examples
///
/// ```no_run
/// # use crx3_rs::{Crx3File, Result};
/// # fn example() -> Result<()> {
/// // Read a CRX file from disk
/// let crx = Crx3File::from_file("extension.crx")?;
///
/// // Verify the signature
/// crx.verify()?;
///
/// // Extract the extension ID
/// let crx_id = crx.get_crx_id()?;
///
/// // Extract the ZIP contents
/// crx.extract_zip("extension.zip")?;
/// # Ok(())
/// # }
/// ```
pub struct Crx3File {
    /// The CRX3 file header containing signatures and metadata
    header: CrxFileHeader,
    /// The ZIP content of the Chrome extension
    zip_data: Vec<u8>,
}

impl Crx3Builder {
    /// Creates a new `Crx3Builder` from a private key and ZIP data.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The RSA private key used for signing
    /// * `zip_data` - The ZIP content as a byte vector
    pub fn new(private_key: RsaPrivateKey, zip_data: Vec<u8>) -> Self {
        Self {
            private_key,
            zip_data,
        }
    }

    /// Creates a new `Crx3Builder` from a private key and ZIP file path.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The RSA private key used for signing
    /// * `zip_path` - The path to the ZIP file
    ///
    /// # Returns
    ///
    /// A `Result` containing a new `Crx3Builder` instance or an error
    pub fn from_zip_path<P: AsRef<Path>>(private_key: RsaPrivateKey, zip_path: P) -> Result<Self> {
        let zip_data = fs::read(zip_path)?;
        Ok(Self::new(private_key, zip_data))
    }

    /// Creates a new `Crx3Builder` from a private key and a reader.
    ///
    /// This reads from the provided reader to get the ZIP content.
    /// Useful when working with network streams or other sources that implement `Read`.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The RSA private key used for signing
    /// * `reader` - Any type that implements `Read`
    ///
    /// # Returns
    ///
    /// A `Result` containing a new `Crx3Builder` instance or an error
    pub fn from_reader<R: Read>(private_key: RsaPrivateKey, mut reader: R) -> Result<Self> {
        let mut zip_data = Vec::new();
        reader.read_to_end(&mut zip_data)?;
        Ok(Self::new(private_key, zip_data))
    }

    /// Builds a CRX3 file from the provided ZIP data and private key.
    ///
    /// This method performs all necessary steps to create a valid CRX3 file:
    /// 1. Derives the extension ID from the public key
    /// 2. Creates and signs the header data
    /// 3. Assembles the CRX3 file structure
    ///
    /// # Returns
    ///
    /// A `Result` containing the fully constructed `Crx3File` or an error
    pub fn build(self) -> Result<Crx3File> {
        // Generate public key
        let public_key = self.private_key.to_public_key();
        let public_key_der = public_key.to_public_key_der()?;

        // Create signed data (CRX ID is derived from public key)
        let crx_id = get_crx_id(public_key_der.as_bytes())?;
        let signed_data = SignedData {
            crx_id: Some(crx_id),
        };

        // Encode signed_data
        let mut signed_header_data = Vec::new();
        signed_data.encode(&mut signed_header_data)?;

        // Prepare data to sign using the common function
        let data_to_sign = prepare_signed_data(&signed_header_data, &self.zip_data);

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
    /// Creates a `Crx3File` from a file path.
    ///
    /// This opens the file at the specified path and parses it as a CRX3 file.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the CRX3 file
    ///
    /// # Returns
    ///
    /// A `Result` containing the parsed `Crx3File` or an error
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = fs::read(path)?;
        Self::from_bytes(&data)
    }

    /// Creates a `Crx3File` from a byte slice.
    ///
    /// This parses the provided bytes as a CRX3 file. Useful for in-memory processing
    /// or when working with web servers where file I/O isn't used.
    ///
    /// # Arguments
    ///
    /// * `data` - The CRX3 file as a byte slice
    ///
    /// # Returns
    ///
    /// A `Result` containing the parsed `Crx3File` or an error
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        Self::from_reader(&mut cursor)
    }

    /// Creates a `Crx3File` from a reader.
    ///
    /// This reads from the provided reader and parses the data as a CRX3 file.
    /// Useful when working with network streams or other sources that implement `Read`.
    ///
    /// # Arguments
    ///
    /// * `reader` - Any type that implements `Read`
    ///
    /// # Returns
    ///
    /// A `Result` containing the parsed `Crx3File` or an error
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        if magic != *CRX3_MAGIC {
            return Err(Error::InvalidFormat(
                "Not a valid CRX3 file (invalid magic)".into(),
            ));
        }

        let mut version = [0u8; 4];
        reader.read_exact(&mut version)?;
        let version = u32::from_le_bytes(version);

        if version != CRX3_VERSION {
            return Err(Error::InvalidFormat(format!(
                "Unsupported CRX version: {}",
                version
            )));
        }

        let mut header_size = [0u8; 4];
        reader.read_exact(&mut header_size)?;
        let header_size = u32::from_le_bytes(header_size);

        let mut header_data = vec![0u8; header_size as usize];
        reader.read_exact(&mut header_data)?;

        let header = CrxFileHeader::decode(&header_data[..])?;

        let mut zip_data = Vec::new();
        reader.read_to_end(&mut zip_data)?;

        Ok(Self { header, zip_data })
    }

    /// Verifies the signature of the CRX3 file.
    ///
    /// This method verifies that the CRX3 file has a valid signature using the
    /// embedded public key. It performs various validation checks to ensure
    /// the file's integrity and authenticity.
    ///
    /// # Returns
    ///
    /// A `Result` indicating whether the verification succeeded (`Ok(())`) or
    /// an error describing why verification failed
    pub fn verify(&self) -> Result<()> {
        // Check if there are any RSA signatures
        if self.header.sha256_with_rsa.is_empty() {
            return Err(Error::NoSignature);
        }
        // Check if there are multiple RSA signatures
        if self.header.sha256_with_rsa.len() > 1 {
            return Err(Error::MultipleSignatures);
        }
        // Check if there are any ECDSA signatures (warning only)
        if !self.header.sha256_with_ecdsa.is_empty() {
            return Err(Error::EcdsaNotSupported);
        }

        // Get the signed header data
        let signed_header_data = match &self.header.signed_header_data {
            Some(data) => data,
            None => {
                return Err(Error::NoSignedHeader);
            }
        };

        // Prepare data for verification using the common function
        let data_to_verify = prepare_signed_data(signed_header_data, &self.zip_data);

        // Try to verify with each RSA signature
        for proof in self.header.sha256_with_rsa.iter() {
            // Extract public key
            let public_key_data = match &proof.public_key {
                Some(data) => data,
                None => {
                    continue;
                }
            };

            // Extract signature
            let signature = match &proof.signature {
                Some(data) => data,
                None => {
                    continue;
                }
            };

            // Parse public key
            let public_key = match RsaPublicKey::from_public_key_der(public_key_data) {
                Ok(key) => key,
                Err(_e) => {
                    continue;
                }
            };

            // Verify signature
            return verify_signature(&public_key, &data_to_verify, signature);
        }

        // If we get here, no signatures verified successfully
        Err(Error::SignatureVerification)
    }

    /// Writes the CRX3 file to a file path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path where the CRX3 file will be written
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let data = self.to_bytes()?;
        fs::write(path, data)?;
        Ok(())
    }

    /// Converts the CRX3 file to a byte vector.
    ///
    /// This serializes the CRX3 file to a `Vec<u8>` for in-memory processing
    /// or sending over a network.
    ///
    /// # Returns
    ///
    /// A `Result` containing the serialized CRX3 file as bytes or an error
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        self.write_to(&mut data)?;
        Ok(data)
    }

    /// Writes the CRX3 file to a writer.
    ///
    /// This serializes the CRX3 file and writes it to any type that implements `Write`.
    /// Useful when working with network streams or other destinations that implement `Write`.
    ///
    /// # Arguments
    ///
    /// * `writer` - Any type that implements `Write`
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error
    pub fn write_to<W: Write>(&self, mut writer: W) -> Result<()> {
        // Write magic number
        writer.write_all(CRX3_MAGIC)?;

        // Write version
        writer.write_all(&CRX3_VERSION.to_le_bytes())?;

        // Encode header
        let mut header_data = Vec::new();
        self.header.encode(&mut header_data)?;

        // Write header size and data
        writer.write_all(&(header_data.len() as u32).to_le_bytes())?;
        writer.write_all(&header_data)?;

        // Write ZIP data
        writer.write_all(&self.zip_data)?;

        Ok(())
    }

    /// Extracts the ZIP content to a file.
    ///
    /// # Arguments
    ///
    /// * `path` - The path where the ZIP content will be written
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error
    pub fn extract_zip<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        fs::write(path, &self.zip_data)?;
        Ok(())
    }

    /// Gets the ZIP content as a byte slice.
    ///
    /// This provides direct access to the ZIP content for in-memory processing.
    ///
    /// # Returns
    ///
    /// A byte slice containing the ZIP content
    pub fn get_zip_content(&self) -> &[u8] {
        &self.zip_data
    }

    /// Gets the Chrome extension ID in raw binary format.
    ///
    /// The extension ID is a 16-byte identifier derived from the public key.
    /// This method extracts the raw ID from the CRX file's signed header data.
    /// To get the formatted ID in Chrome's standard format, use the `format_extension_id`
    /// function on the result of this method.
    ///
    /// # Returns
    ///
    /// A `Result` containing the raw extension ID as a `Vec<u8>` or an error
    /// if no extension ID was found
    pub fn get_crx_id(&self) -> Result<Vec<u8>> {
        if let Some(signed_header_data) = &self.header.signed_header_data {
            let signed_data = SignedData::decode(&signed_header_data[..])?;

            if let Some(crx_id) = signed_data.crx_id {
                return Ok(crx_id);
            }
        }

        Err(Error::NoCrxId)
    }
}

// Helper functions

fn get_crx_id(public_key_data: &[u8]) -> Result<Vec<u8>> {
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

/// Formats a raw extension ID (16 bytes) to the Chrome extension ID format.
///
/// Chrome extension IDs are displayed as 32-character lowercase strings using
/// characters a-p (representing 16 bytes encoded as base16 with an offset).
///
/// # Arguments
///
/// * `raw_id` - The raw binary extension ID (typically 16 bytes obtained from `get_crx_id`)
///
/// # Returns
///
/// A String containing the formatted extension ID in Chrome's standard format.
///
/// # Examples
///
/// ```
/// # use crx3_rs::{Crx3File, format_extension_id, Result};
/// # fn example() -> Result<()> {
/// # let crx = Crx3File::from_file("testdata/chrome-extension.crx")?;
/// let raw_id = crx.get_crx_id()?;
/// let extension_id = format_extension_id(&raw_id);
/// // Result will be a string like "cdofnkkjddjieacnedgfcbndilidfihj"
/// # Ok(())
/// # }
/// ```
pub fn format_extension_id(raw_id: &[u8]) -> String {
    // Chrome uses base26 (a-z) encoding with an offset of 10 (0->a, 9->j, 15->p)
    // Reference: golang implementation of Chrome extension ID format

    // First convert each byte to 2 hex characters
    let hex_string = {
        let mut s = String::with_capacity(raw_id.len() * 2);
        for &b in raw_id {
            use std::fmt::Write;
            write!(s, "{:02x}", b).unwrap();
        }
        s
    };

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

/// Trait representing CRX3 data preparation and signature operations
///
/// This trait defines the operations needed for CRX3 file signing and verification.
/// It separates the data preparation logic from the actual cryptographic operations,
/// making it easier to change or extend the signature scheme in the future.
pub trait SignatureOperation {
    /// Prepare data for signing or verification from CRX3 components
    ///
    /// This creates the data blob that will be signed or verified according to the
    /// Chrome Extension format specification.
    fn prepare_data(&self, signed_header_data: &[u8], zip_data: &[u8]) -> Vec<u8>;

    /// Sign the data with the private key
    ///
    /// # Arguments
    /// * `private_key` - The RSA private key used for signing
    /// * `data` - The data to be signed
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The signature bytes or an error
    fn sign(&self, private_key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>>;

    /// Verify the signature with the public key
    ///
    /// # Arguments
    /// * `public_key` - The RSA public key used for verification
    /// * `data` - The data that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// * `Result<()>` - Ok if verification succeeds, or an error
    fn verify(&self, public_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> Result<()>;
}

/// Chrome CRX3 signature scheme implementation using PKCS#1 v1.5 with SHA-256
struct Crx3Signature;

impl SignatureOperation for Crx3Signature {
    /// Prepares data for signing or verification according to the CRX3 format specification.
    ///
    /// This method creates a data blob with the following format:
    /// - Magic bytes: "CRX3 SignedData\0"
    /// - Header size (4 bytes, little-endian)
    /// - Header data
    /// - ZIP content
    ///
    /// # Arguments
    /// * `signed_header_data` - The encoded signed header protobuf message
    /// * `zip_data` - The ZIP file content
    ///
    /// # Returns
    /// A `Vec<u8>` containing the prepared data ready for signing or verification
    fn prepare_data(&self, signed_header_data: &[u8], zip_data: &[u8]) -> Vec<u8> {
        let signed_header_size = signed_header_data.len() as u32;
        let mut data = b"CRX3 SignedData\x00".to_vec();
        data.extend_from_slice(&signed_header_size.to_le_bytes());
        data.extend_from_slice(signed_header_data);
        data.extend_from_slice(zip_data);
        data
    }

    /// Signs data with the private key using PKCS#1 v1.5 with SHA-256.
    ///
    /// This method creates a signature for the provided data using the specified RSA private key.
    /// It first hashes the data using SHA-256 and then signs the hash with PKCS#1 v1.5.
    ///
    /// # Arguments
    /// * `private_key` - The RSA private key to sign with
    /// * `data` - The data to sign
    ///
    /// # Returns
    /// A `Result` containing the signature as a `Vec<u8>` or an error
    fn sign(&self, private_key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>> {
        use rsa::sha2::{Digest, Sha256};

        // Calculate the SHA-256 hash of the data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        // Sign with PKCS#1 v1.5
        let signature = private_key.sign(Pkcs1v15Sign::new::<Sha256>(), &hash)?;

        Ok(signature.to_vec())
    }

    /// Verifies a signature using the public key with PKCS#1 v1.5 and SHA-256.
    ///
    /// This method verifies that the signature for the provided data is valid using
    /// the specified RSA public key. It first hashes the data using SHA-256 and then
    /// verifies the signature using PKCS#1 v1.5.
    ///
    /// # Arguments
    /// * `public_key` - The RSA public key to verify with
    /// * `data` - The data that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// A `Result` indicating whether verification succeeded (`Ok(())`) or an error
    fn verify(&self, public_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> Result<()> {
        use rsa::sha2::{Digest, Sha256};

        // Calculate the SHA-256 hash of the data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        // Verify with PKCS#1 v1.5
        public_key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &hash, signature)
            .map_err(|_| Error::SignatureVerification)
    }
}

// Use Chrome CRX3 signature scheme with PKCS#1 v1.5 for Chrome Extension signing
static SIGNATURE_SCHEME: Crx3Signature = Crx3Signature {};

/// Prepare data for signing or verification in the Chrome Extension format
///
/// Creates a blob containing the header magic, header size, header data, and ZIP content
/// according to the Chrome Extension format specification.
///
/// # Arguments
/// * `signed_header_data` - The encoded SignedData protobuf message
/// * `zip_data` - The ZIP file content
///
/// # Returns
/// The prepared data ready for signing or verification
fn prepare_signed_data(signed_header_data: &[u8], zip_data: &[u8]) -> Vec<u8> {
    SIGNATURE_SCHEME.prepare_data(signed_header_data, zip_data)
}

/// Sign the prepared data with a private key
///
/// # Arguments
/// * `private_key` - The RSA private key to sign with
/// * `data` - The data to sign (should be prepared with prepare_signed_data)
///
/// # Returns
/// * `Result<Vec<u8>>` - The signature or an error
fn sign_data(private_key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>> {
    SIGNATURE_SCHEME.sign(private_key, data)
}

/// Verify a signature with a public key
///
/// # Arguments
/// * `public_key` - The RSA public key to verify with
/// * `signed_data` - The data that was signed (should be prepared with prepare_signed_data)
/// * `signature` - The signature to verify
///
/// # Returns
/// * `Result<()>` - Ok if verification succeeds, or an error
fn verify_signature(public_key: &RsaPublicKey, signed_data: &[u8], signature: &[u8]) -> Result<()> {
    SIGNATURE_SCHEME.verify(public_key, signed_data, signature)
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

        // Verify it - now fixed with consistent signature algorithm
        assert!(loaded_crx.verify().is_ok());

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

    #[test]
    fn test_in_memory_processing() {
        // Generate a test key
        let private_key = generate_test_key();

        // Create a test ZIP
        let zip_data = create_test_zip();

        // Build a CRX file
        let builder = Crx3Builder::new(private_key, zip_data.clone());
        let crx = builder.build().unwrap();

        // Convert to bytes
        let crx_bytes = crx.to_bytes().unwrap();

        // Read it back from bytes
        let loaded_crx = Crx3File::from_bytes(&crx_bytes).unwrap();

        // Verify it
        assert!(loaded_crx.verify().is_ok());

        // Check ZIP content
        assert_eq!(loaded_crx.get_zip_content(), zip_data.as_slice());
    }

    #[test]
    fn test_reader_writer() {
        // Generate a test key
        let private_key = generate_test_key();

        // Create a test ZIP in a cursor
        let zip_data = create_test_zip();
        let mut zip_cursor = std::io::Cursor::new(zip_data.clone());

        // Build a CRX file from reader
        let builder = Crx3Builder::from_reader(private_key, &mut zip_cursor).unwrap();
        let crx = builder.build().unwrap();

        // Write to a buffer
        let mut buffer = Vec::new();
        crx.write_to(&mut buffer).unwrap();

        // Read it back from the buffer
        let mut read_cursor = std::io::Cursor::new(buffer);
        let loaded_crx = Crx3File::from_reader(&mut read_cursor).unwrap();

        // Verify it
        assert!(loaded_crx.verify().is_ok());

        // Check ZIP content
        assert_eq!(loaded_crx.get_zip_content(), zip_data.as_slice());
    }
}
