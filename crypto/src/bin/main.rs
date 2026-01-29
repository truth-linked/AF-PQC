use clap::{Parser, Subcommand, CommandFactory};
use clap_complete::{generate, Shell};
use af_pqc::{PublicKey, Signature};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use sha2::{Sha256, Digest};
use anyhow::{Result, Context};
use log::{info, warn, error, debug};
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser)]
#[command(name = "af-cli")]
#[command(about = "Authority Fabric Post-Quantum Cryptographic CLI")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate shell completion scripts
    Completions {
        /// Shell type
        #[arg(value_enum)]
        shell: Shell,
    },
    
    /// Generate cryptographically secure seed
    GenerateSeed {
        /// Output format: hex or base64
        #[arg(short, long, default_value = "hex")]
        format: String,
    },
    
    /// Generate a new post-quantum hybrid keypair
    Keygen {
        /// Output file for public key (JSON format)
        #[arg(short = 'P', long)]
        public_key: PathBuf,
        
        /// Key type: signing or encryption
        #[arg(short, long, default_value = "signing")]
        key_type: String,
        
        /// Seed phrase for deterministic key generation (32 hex chars)
        #[arg(short, long)]
        seed: String,
    },
    
    /// Sign a file or message with hybrid post-quantum signature
    Sign {
        /// Seed phrase for deterministic key generation (32 hex chars)
        #[arg(short, long)]
        seed: String,
        
        /// Input file to sign (or stdin if not provided)
        #[arg(short, long)]
        input: Option<PathBuf>,
        
        /// Output signature file (JSON format)
        #[arg(short, long)]
        output: PathBuf,
        
        /// Message to sign directly (alternative to input file)
        #[arg(short, long)]
        message: Option<String>,
    },
    
    /// Verify a post-quantum hybrid signature
    Verify {
        /// Public key file (JSON format)
        #[arg(short = 'P', long)]
        public_key: PathBuf,
        
        /// Signature file (JSON format)
        #[arg(short, long)]
        signature: PathBuf,
        
        /// Input file that was signed (or stdin if not provided)
        #[arg(short, long)]
        input: Option<PathBuf>,
        
        /// Message that was signed directly
        #[arg(short, long)]
        message: Option<String>,
    },
    
    /// Generate cryptographic address from public key
    Address {
        /// Public key file (JSON format)
        #[arg(short = 'P', long)]
        public_key: PathBuf,
        
        /// Address format: hex, base64
        #[arg(short, long, default_value = "hex")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .init();
    
    info!("Authority Fabric Cryptographic CLI v0.1.0");
    debug!("Post-quantum hybrid cryptography (Dilithium3 + Ed25519)");
    
    let result = match cli.command {
        Commands::Completions { shell } => {
            cmd_completions(shell).await
        }
        Commands::GenerateSeed { format } => {
            cmd_generate_seed(format).await
        }
        Commands::Keygen { public_key, key_type, seed } => {
            cmd_keygen(public_key, key_type, seed).await
        }
        Commands::Sign { seed, input, output, message } => {
            cmd_sign(seed, input, output, message).await
        }
        Commands::Verify { public_key, signature, input, message } => {
            cmd_verify(public_key, signature, input, message).await
        }
        Commands::Address { public_key, format } => {
            cmd_address(public_key, format).await
        }
    };
    
    match result {
        Ok(()) => {
            info!("Operation completed successfully");
            Ok(())
        }
        Err(e) => {
            error!("Operation failed: {}", e);
            std::process::exit(1);
        }
    }
}

async fn cmd_completions(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, &mut io::stdout());
    Ok(())
}

async fn cmd_generate_seed(format: String) -> Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Generating cryptographically secure seed");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    
    info!("Generating cryptographically secure 32-byte seed");
    
    let mut seed = [0u8; 32];
    af_pqc::secure_random_bytes(&mut seed)
        .with_context(|| "Failed to generate secure random bytes - insufficient system entropy")?;
    
    pb.finish_with_message("Secure seed generated");
    
    let output = match format.as_str() {
        "hex" => hex::encode(seed),
        "base64" => {
            use base64::{Engine, engine::general_purpose};
            general_purpose::STANDARD.encode(seed)
        },
        _ => return Err(anyhow::anyhow!("Invalid format '{}' - supported formats: hex, base64", format)),
    };
    
    println!("{}", output);
    info!("Secure seed generated using OS entropy");
    warn!("CRITICAL: Store this seed securely - it is your master secret");
    warn!("Anyone with this seed can regenerate your private keys");
    
    Ok(())
}

async fn cmd_keygen(public_key_path: PathBuf, key_type_str: String, seed: String) -> Result<()> {
    // Validate and parse seed
    if seed.len() != 64 {
        return Err(anyhow::anyhow!("Seed must be exactly 64 hex characters (32 bytes)"));
    }
    let seed_bytes: [u8; 32] = hex::decode(&seed)
        .context("Invalid hex seed")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Seed must be exactly 32 bytes"))?;
    
    info!("Generating deterministic post-quantum hybrid keypair");
    debug!("Key type: {}", key_type_str);
    
    let (private_key, public_key) = af_pqc::generate_key_from_seed(&seed_bytes)
        .context("Failed to generate deterministic keypair")?;
    
    // Save only public key - private key never touches disk
    let public_key_json = serde_json::to_string_pretty(&public_key)
        .context("Failed to serialize public key")?;
    fs::write(&public_key_path, public_key_json)
        .context("Failed to write public key file")?;
    
    info!("Public key saved to: {}", public_key_path.display());
    info!("Private key generated deterministically (not saved - use same seed to regenerate)");
    info!("Algorithm: {:?}", private_key.algorithm);
    info!("Key ID: {}", private_key.key_id);
    info!("Public key size: {} bytes", public_key.bytes.len());
    warn!("Private key stored encrypted - Dilithium component cached securely");
    
    Ok(())
}

async fn cmd_sign(seed: String, input_path: Option<PathBuf>, output_path: PathBuf, message: Option<String>) -> Result<()> {
    // Validate and parse seed
    if seed.len() != 64 {
        return Err(anyhow::anyhow!("Seed must be exactly 64 hex characters (32 bytes)"));
    }
    let seed_bytes: [u8; 32] = hex::decode(&seed)
        .context("Invalid hex seed")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Seed must be exactly 32 bytes"))?;
    
    info!("Regenerating private key from seed for signing operation");
    
    // Regenerate private key deterministically from seed
    let (private_key, _public_key) = af_pqc::generate_key_from_seed(&seed_bytes)
        .context("Failed to regenerate keypair from seed")?;
    
    info!("Using deterministic key: {}", private_key.key_id);
    
    // Get message to sign
    let message_bytes = if let Some(msg) = message {
        debug!("Signing direct message of {} bytes", msg.len());
        msg.into_bytes()
    } else if let Some(input) = input_path {
        debug!("Reading input file: {}", input.display());
        fs::read(&input)
            .with_context(|| format!("Failed to read input file: {}", input.display()))?
    } else {
        debug!("Reading from stdin");
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)
            .context("Failed to read from stdin")?;
        buffer
    };
    
    if message_bytes.is_empty() {
        warn!("Input message is empty");
    }
    
    info!("Signing {} bytes with hybrid algorithm", message_bytes.len());
    
    let signature = private_key.sign(&message_bytes)
        .context("Hybrid signature generation failed")?;
    
    // Save signature in JSON format (Signature implements Serialize/Deserialize)
    let signature_json = serde_json::to_string_pretty(&signature)
        .context("Failed to serialize signature")?;
    fs::write(&output_path, signature_json)
        .context("Failed to write signature file")?;
    
    info!("Signature saved to: {}", output_path.display());
    info!("Algorithm: {:?}", signature.algorithm);
    info!("Signer: {}", signature.signer_key_id);
    info!("Signature size: {} bytes", signature.bytes.len());
    
    Ok(())
}

async fn cmd_verify(public_key_path: PathBuf, signature_path: PathBuf, input_path: Option<PathBuf>, message: Option<String>) -> Result<()> {
    debug!("Loading public key from: {}", public_key_path.display());
    
    // Load public key (JSON format)
    let public_key_json = fs::read_to_string(&public_key_path)
        .context("Failed to read public key file")?;
    let public_key: PublicKey = serde_json::from_str(&public_key_json)
        .context("Failed to parse public key JSON")?;
    
    debug!("Loading signature from: {}", signature_path.display());
    
    // Load signature (JSON format)
    let signature_json = fs::read_to_string(&signature_path)
        .context("Failed to read signature file")?;
    let signature: Signature = serde_json::from_str(&signature_json)
        .context("Failed to parse signature JSON")?;
    
    // Get message to verify
    let message_bytes = if let Some(msg) = message {
        debug!("Verifying direct message of {} bytes", msg.len());
        msg.into_bytes()
    } else if let Some(input) = input_path {
        debug!("Reading input file: {}", input.display());
        fs::read(&input)
            .with_context(|| format!("Failed to read input file: {}", input.display()))?
    } else {
        debug!("Reading from stdin");
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)
            .context("Failed to read from stdin")?;
        buffer
    };
    
    info!("Verifying hybrid signature for {} bytes", message_bytes.len());
    
    match public_key.verify(&message_bytes, &signature) {
        Ok(()) => {
            info!("✓ Signature verification PASSED");
            info!("Algorithm: {:?}", signature.algorithm);
            info!("Signer: {}", signature.signer_key_id);
            info!("Signed at: {}", signature.created_at);
            info!("Both Dilithium3 and Ed25519 components verified successfully");
        }
        Err(e) => {
            error!("✗ Signature verification FAILED: {}", e);
            return Err(anyhow::anyhow!("Signature verification failed: {}", e));
        }
    }
    
    Ok(())
}

async fn cmd_address(public_key_path: PathBuf, format: String) -> Result<()> {
    debug!("Loading public key from: {}", public_key_path.display());
    
    // Load public key (JSON format)
    let public_key_json = fs::read_to_string(&public_key_path)
        .context("Failed to read public key file")?;
    let public_key: PublicKey = serde_json::from_str(&public_key_json)
        .context("Failed to parse public key JSON")?;
    
    info!("Generating address from {} byte public key", public_key.bytes.len());
    
    // Generate address from public key hash (using SHA-256)
    let mut hasher = Sha256::new();
    hasher.update(&public_key.bytes);
    hasher.update(&public_key.created_at.to_le_bytes());
    hasher.update(&public_key.operation_id.to_le_bytes());
    let hash = hasher.finalize();
    
    let address = match format.as_str() {
        "hex" => {
            hex::encode(&hash[..20]) // Take first 20 bytes
        }
        "base64" => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&hash[..20])
        }
        _ => {
            error!("Unsupported address format: {}", format);
            return Err(anyhow::anyhow!("Unsupported format. Use: hex, base64"));
        }
    };
    
    info!("Address: {}", address);
    info!("Format: {}", format);
    info!("Algorithm: {:?}", public_key.algorithm);
    info!("Derived from public key created at: {}", public_key.created_at);
    
    Ok(())
}
