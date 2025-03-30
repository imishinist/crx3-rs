use crx3_rs::{Crx3Builder, Crx3File};
use rsa::pkcs8::DecodePrivateKey;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

fn load_private_key<P: AsRef<Path>>(file_name: P) -> io::Result<rsa::RsaPrivateKey> {
    let mut file = fs::File::open(&file_name).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Unable to open key file {}: {}",
                file_name.as_ref().display(),
                e
            ),
        )
    })?;

    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to read key file: {}", e),
        )
    })?;

    let key = rsa::RsaPrivateKey::from_pkcs8_pem(&contents).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to parse private key: {}", e),
        )
    })?;

    Ok(key)
}

fn create_crx(zip_path: &str, private_key_path: &str, output_path: &str) -> io::Result<()> {
    println!("Creating CRX from ZIP: {}", zip_path);

    // Load private key
    let private_key = load_private_key(private_key_path)?;

    // Create CRX builder from ZIP
    let builder = Crx3Builder::from_zip_path(private_key, zip_path)?;

    // Build CRX
    let crx = builder.build()?;

    // Write to file
    crx.write_to_file(output_path)?;

    println!("Successfully created CRX at: {}", output_path);
    Ok(())
}

fn verify_crx(crx_path: &str) -> io::Result<()> {
    println!("Verifying CRX file: {}", crx_path);

    // Load CRX file
    let crx = Crx3File::from_file(crx_path)?;

    // Verify signature
    match crx.verify() {
        Ok(_) => {
            println!("Signature verification: SUCCESS");

            // Also get the extension ID
            match crx.get_crx_id() {
                Ok(crx_id) => {
                    // Format using Chrome's extension ID format (a-p character encoding)
                    let chrome_app_id = crx3_rs::format_extension_id(&crx_id);
                    println!("Chrome Extension ID: {}", chrome_app_id);
                }
                Err(e) => {
                    eprintln!("Could not read extension ID: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Signature verification: FAILED");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Signature verification failed: {}", e),
            ));
        }
    }
    Ok(())
}

fn extract_crx(crx_path: &str, output_path: &str) -> io::Result<()> {
    println!("Extracting ZIP from CRX: {}", crx_path);

    // Load CRX file
    let crx = Crx3File::from_file(crx_path)?;

    // Extract ZIP
    crx.extract_zip(output_path)?;

    println!("Successfully extracted ZIP to: {}", output_path);
    Ok(())
}

fn get_crx_id(crx_path: &str) -> io::Result<()> {
    // Load CRX file
    let crx = Crx3File::from_file(crx_path)?;

    // Get CRX ID (extension ID)
    let crx_id = crx.get_crx_id()?;

    // Format using Chrome's extension ID format (a-p character encoding)
    let chrome_app_id = crx3_rs::format_extension_id(&crx_id);

    // Print Chrome-style extension ID (this is what appears in Chrome URLs)
    println!("{}", chrome_app_id);

    Ok(())
}

fn print_usage() {
    println!("Usage:");
    println!("  crx3rs create <zip_path> <private_key_path> <output_crx_path>");
    println!("  crx3rs verify <crx_path>");
    println!("  crx3rs extract <crx_path> <output_zip_path>");
    println!("  crx3rs id <crx_path>");
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    match args[1].as_str() {
        "create" => {
            if args.len() != 5 {
                println!("Error: 'create' requires 3 arguments");
                print_usage();
                return Ok(());
            }
            create_crx(&args[2], &args[3], &args[4])
        }
        "verify" => {
            if args.len() != 3 {
                println!("Error: 'verify' requires 1 argument");
                print_usage();
                return Ok(());
            }
            verify_crx(&args[2])
        }
        "extract" => {
            if args.len() != 4 {
                println!("Error: 'extract' requires 2 arguments");
                print_usage();
                return Ok(());
            }
            extract_crx(&args[2], &args[3])
        }
        "id" => {
            if args.len() != 3 {
                println!("Error: 'id' requires 1 argument");
                print_usage();
                return Ok(());
            }
            get_crx_id(&args[2])
        }
        _ => {
            println!("Unknown command: {}", args[1]);
            print_usage();
            Ok(())
        }
    }
}
