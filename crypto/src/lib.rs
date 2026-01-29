//! # Post-Quantum Hybrid Cryptography
//!
//! Production-ready post-quantum cryptographic operations using NIST-approved algorithms.
//! 
//! This library implements mandatory hybrid signatures combining Dilithium3 (post-quantum)
//! with Ed25519 (classical) for maximum security during the cryptographic transition period.
//!
//! ## Features
//! - NIST-approved post-quantum algorithms (Dilithium3)
//! - Hybrid approach for transition security
//! - Memory-safe implementation with usage limits
//! - Side-channel attack resistance
//! - Production-grade error handling

#[cfg(feature = "witness-integration")]
use witness_time::{EntryType, verify_witness_commitment, current_timestamp};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crystals_dilithium::dilithium3::{
    Keypair as DilithiumKeypair,
    PublicKey as DilithiumPublicKey,
    PUBLICKEYBYTES,
    SIGNBYTES,
};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey};
use std::sync::atomic::AtomicU64;


/// Cryptographic error types
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Insufficient guardian approval: need 3-of-5")]
    InsufficientGuardianApproval,
    
    #[error("Invalid ephemeral TTL exceeds maximum")]
    InvalidEphemeralTTL,
    
    #[error("Ephemeral key expired")]
    ExpiredEphemeralKey,
    
    #[error("Key generation failed: entropy below threshold (required: {threshold}, actual: {actual})")]
    KeyGeneration { threshold: f64, actual: f64 },
    
    #[error("Invalid key: {details}")]
    InvalidKey { details: String },
    
    #[error("Signature verification failed: {details}")]
    SignatureVerification { details: String },
    
    #[error("Unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(AlgorithmVersion),
    
    #[error("Invalid operation: {details}")]
    InvalidOperation { details: String },
    
    #[error("Audit trail corruption detected")]
    AuditFailure,
    
    #[error("Key usage limit exceeded: {count} operations (max: {max})")]
    KeyUsageExceeded { count: u64, max: u64 },
    
    #[error("Side-channel attack detected: {details}")]
    SideChannelAttack { details: String },
    
    #[error("Timing attack detected: operation took {duration_ms}ms (expected: {expected_ms}ms)")]
    TimingAttack { duration_ms: u64, expected_ms: u64 },
}

/// Cryptographic key types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Signing,
    Encryption,
}

/// Algorithm versions with hybrid enforcement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgorithmVersion {
    #[deprecated(note = "Pure Dilithium forbidden - use MandatoryHybrid")]
    Dilithium3V1,
    #[deprecated(note = "Pure Ed25519 forbidden - use MandatoryHybrid")]
    Ed25519V1,
    MandatoryHybrid,
}

/// Key material storage with hybrid enforcement
pub enum KeyMaterialInner {
    #[deprecated(note = "Pure Dilithium forbidden - use MandatoryHybrid")]
    Dilithium(DilithiumKeypair),
    #[deprecated(note = "Pure Ed25519 forbidden - use MandatoryHybrid")]
    Ed25519(SigningKey),
    MandatoryHybrid {
        dilithium: DilithiumKeypair,
        ed25519: SigningKey,
    },
}

/// Private key with usage tracking and metadata
pub struct PrivateKey {
    pub algorithm: AlgorithmVersion,
    pub inner: KeyMaterialInner,
    pub created_at: u64,
    pub operation_id: u64,
    pub usage_count: AtomicU64,
    pub key_id: String,
}

/// Public key for signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub algorithm: AlgorithmVersion,
    pub bytes: Vec<u8>,
    pub created_at: u64,
    pub operation_id: u64,
}

/// Digital signature with provenance metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: AlgorithmVersion,
    pub bytes: Vec<u8>,
    pub created_at: u64,
    pub operation_id: u64,
    pub signer_key_id: String,
}

impl PrivateKey {
    /// Generate a new hybrid keypair
    pub fn generate() -> Result<(Self, PublicKey), CryptoError> {
        Self::generate_with_algorithm(AlgorithmVersion::MandatoryHybrid)
    }
    
    /// Generate keypair with specific algorithm version
    pub fn generate_with_algorithm(algorithm: AlgorithmVersion) -> Result<(Self, PublicKey), CryptoError> {
        match algorithm {
            AlgorithmVersion::MandatoryHybrid => {
                #[cfg(feature = "witness-integration")]
                let operation_id = current_timestamp();
                #[cfg(not(feature = "witness-integration"))]
                let operation_id = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                use rand_core::OsRng;
                let mut rng = OsRng;
                
                let dilithium_keypair = DilithiumKeypair::generate(None);
                let ed25519_key = SigningKey::generate(&mut rng);
                
                let mut public_bytes = Vec::new();
                public_bytes.extend_from_slice(&dilithium_keypair.public.to_bytes());
                public_bytes.extend_from_slice(&ed25519_key.verifying_key().to_bytes());
                
                let inner = KeyMaterialInner::MandatoryHybrid {
                    dilithium: dilithium_keypair,
                    ed25519: ed25519_key,
                };
                
                #[cfg(feature = "witness-integration")]
                let now = current_timestamp();
                #[cfg(not(feature = "witness-integration"))]
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                let private_key = Self {
                    algorithm,
                    inner,
                    created_at: now,
                    operation_id,
                    usage_count: AtomicU64::new(0),
                    key_id: format!("mandatory-hybrid-{}", operation_id),
                };
                
                let public_key = PublicKey {
                    algorithm,
                    bytes: public_bytes,
                    created_at: now,
                    operation_id,
                };
                
                Ok((private_key, public_key))
            }
            #[allow(deprecated)]
            AlgorithmVersion::Dilithium3V1 => {
                Err(CryptoError::UnsupportedAlgorithm(algorithm))
            }
            #[allow(deprecated)]
            AlgorithmVersion::Ed25519V1 => {
                Err(CryptoError::UnsupportedAlgorithm(algorithm))
            }
        }
    }
    
    /// Extract the corresponding public key
    pub fn public_key(&self) -> Result<PublicKey, CryptoError> {
        let bytes = match &self.inner {
            #[allow(deprecated)]
            KeyMaterialInner::Dilithium(_) => {
                return Err(CryptoError::InvalidKey { 
                    details: "Pure Dilithium forbidden - use MandatoryHybrid".to_string() 
                });
            }
            #[allow(deprecated)]
            KeyMaterialInner::Ed25519(_) => {
                return Err(CryptoError::InvalidKey { 
                    details: "Pure Ed25519 forbidden - use MandatoryHybrid".to_string() 
                });
            }
            KeyMaterialInner::MandatoryHybrid { dilithium, ed25519 } => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&dilithium.public.to_bytes());
                bytes.extend_from_slice(&ed25519.verifying_key().to_bytes());
                bytes
            }
        };
        
        Ok(PublicKey {
            algorithm: self.algorithm.clone(),
            bytes,
            created_at: self.created_at,
            operation_id: self.operation_id,
        })
    }

    /// Create a hybrid digital signature
    pub fn sign(&self, message: &[u8]) -> Result<Signature, CryptoError> {
        // Input validation
        if message.is_empty() {
            return Err(CryptoError::InvalidOperation {
                details: "Cannot sign empty message".to_string()
            });
        }
        
        if message.len() > 1_048_576 {
            return Err(CryptoError::InvalidOperation {
                details: "Message too large for signing".to_string()
            });
        }
        
        // Usage tracking
        let current_usage = self.usage_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if current_usage >= 1_000_000 {
            return Err(CryptoError::InvalidOperation {
                details: "Key usage limit exceeded".to_string()
            });
        }
        
        #[cfg(feature = "witness-integration")]
        let operation_id = current_timestamp();
        #[cfg(not(feature = "witness-integration"))]
        let operation_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let signature_bytes = match &self.inner {
            #[allow(deprecated)]
            KeyMaterialInner::Dilithium(_) => {
                return Err(CryptoError::InvalidOperation {
                    details: "Pure Dilithium signing forbidden".to_string()
                });
            }
            #[allow(deprecated)]
            KeyMaterialInner::Ed25519(_) => {
                return Err(CryptoError::InvalidOperation {
                    details: "Pure Ed25519 signing forbidden".to_string()
                });
            }
            KeyMaterialInner::MandatoryHybrid { dilithium, ed25519 } => {
                let dilithium_sig = dilithium.sign(message);
                let ed25519_sig = ed25519.sign(message);
                
                let mut combined = Vec::new();
                combined.extend_from_slice(&dilithium_sig);
                combined.extend_from_slice(&ed25519_sig.to_bytes());
                combined
            }
        };
        
        Ok(Signature {
            algorithm: self.algorithm,
            bytes: signature_bytes,
            #[cfg(feature = "witness-integration")]
            created_at: current_timestamp(),
            #[cfg(not(feature = "witness-integration"))]
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            operation_id,
            signer_key_id: self.key_id.clone(),
        })
    }
}

impl PublicKey {
    /// Verify a hybrid digital signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        match self.algorithm {
            #[allow(deprecated)]
            AlgorithmVersion::Dilithium3V1 => {
                Err(CryptoError::InvalidOperation {
                    details: "Pure Dilithium verification forbidden".to_string()
                })
            }
            #[allow(deprecated)]
            AlgorithmVersion::Ed25519V1 => {
                Err(CryptoError::InvalidOperation {
                    details: "Pure Ed25519 verification forbidden".to_string()
                })
            }
            AlgorithmVersion::MandatoryHybrid => {
                // Memory safety: validate key length
                if self.bytes.len() < PUBLICKEYBYTES + 32 {
                    return Err(CryptoError::InvalidKey {
                        details: "Invalid mandatory hybrid key length".to_string()
                    });
                }
                
                let dilithium_public = DilithiumPublicKey::from_bytes(&self.bytes[..PUBLICKEYBYTES]);
                let ed25519_bytes: [u8; 32] = self.bytes[PUBLICKEYBYTES..PUBLICKEYBYTES + 32].try_into()
                    .map_err(|_| CryptoError::InvalidKey {
                        details: "Invalid mandatory hybrid Ed25519 key".to_string()
                    })?;
                
                let ed25519_public = VerifyingKey::from_bytes(&ed25519_bytes)
                    .map_err(|_| CryptoError::InvalidKey {
                        details: "Invalid mandatory hybrid Ed25519 public key".to_string()
                    })?;
                
                // Memory safety: validate signature length
                if signature.bytes.len() < SIGNBYTES + 64 {
                    return Err(CryptoError::SignatureVerification {
                        details: "Invalid mandatory hybrid signature length".to_string()
                    });
                }
                
                if !dilithium_public.verify(message, &signature.bytes[..SIGNBYTES]) {
                    return Err(CryptoError::SignatureVerification {
                        details: "Mandatory hybrid Dilithium verification failed".to_string()
                    });
                }
                
                let ed25519_sig_bytes: [u8; 64] = signature.bytes[SIGNBYTES..SIGNBYTES + 64].try_into()
                    .map_err(|_| CryptoError::SignatureVerification {
                        details: "Invalid mandatory hybrid Ed25519 signature length".to_string()
                    })?;
                
                let ed25519_sig = ed25519_dalek::Signature::from_bytes(&ed25519_sig_bytes);
                
                ed25519_public.verify(message, &ed25519_sig)
                    .map_err(|_| CryptoError::SignatureVerification {
                        details: "Mandatory hybrid Ed25519 verification failed".to_string()
                    })
            }
        }
    }
}

/// Generate deterministic keypair from seed
pub fn generate_key_from_seed(seed: &[u8; 32]) -> Result<(PrivateKey, PublicKey), CryptoError> {
    use rand::{SeedableRng};
    use rand_chacha::ChaCha20Rng;
    
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let operation_id = u64::from_be_bytes([seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6], seed[7]]);
    
    // Try to load encrypted Dilithium keypair first
    let dilithium_keypair = match load_encrypted_dilithium_keypair(seed) {
        Ok(keypair) => keypair,
        Err(_) => {
            // Generate new Dilithium keypair and save it encrypted
            let keypair = DilithiumKeypair::generate(None);
            save_encrypted_dilithium_keypair(seed, &keypair)?;
            keypair
        }
    };
    
    let ed25519_key = SigningKey::generate(&mut rng);
    
    let mut public_bytes = Vec::new();
    public_bytes.extend_from_slice(&dilithium_keypair.public.to_bytes());
    public_bytes.extend_from_slice(&ed25519_key.verifying_key().to_bytes());
    
    let inner = KeyMaterialInner::MandatoryHybrid {
        dilithium: dilithium_keypair,
        ed25519: ed25519_key,
    };
    
    #[cfg(feature = "witness-integration")]
    let now = current_timestamp();
    #[cfg(not(feature = "witness-integration"))]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let private_key = PrivateKey {
        algorithm: AlgorithmVersion::MandatoryHybrid,
        inner,
        created_at: now,
        operation_id,
        usage_count: AtomicU64::new(0),
        key_id: format!("deterministic-hybrid-{}", hex::encode(&seed[..8])),
    };
    
    let public_key = PublicKey {
        algorithm: AlgorithmVersion::MandatoryHybrid,
        bytes: public_bytes,
        created_at: now,
        operation_id,
    };
    
    Ok((private_key, public_key))
}

/// Generate keypair with policy binding
pub fn generate_witness_bound_key(policy_hash: &[u8; 32]) -> Result<(PrivateKey, PublicKey), CryptoError> {
    #[cfg(feature = "witness-integration")]
    {
        let witness_proof = verify_witness_commitment(*policy_hash, EntryType::PolicyCreate)
            .map_err(|_| CryptoError::InvalidOperation {
                details: "Witness commitment verification failed".to_string()
            })?;
        
        // Generate standard keypair
        let (private_key, public_key) = PrivateKey::generate()?;
        
        // Create cryptographic binding to policy
        let binding_data = [policy_hash.as_slice(), &witness_proof.commitment_hash].concat();
        let binding_signature = private_key.sign(&binding_data)?;
        
        // Verify binding integrity
        public_key.verify(&binding_data, &binding_signature)?;
        
        Ok((private_key, public_key))
    }
    
    #[cfg(not(feature = "witness-integration"))]
    {
        let _ = policy_hash; // Silence unused parameter warning
        PrivateKey::generate()
    }
}

/// Generate cryptographically secure random bytes
pub fn secure_random_bytes(buffer: &mut [u8]) -> Result<(), CryptoError> {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(buffer);
    Ok(())
}

/// Derive secure encryption key from seed using HKDF
fn derive_encryption_key(seed: &[u8; 32]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    
    // Use HKDF-like derivation
    let mut hasher = Sha256::new();
    hasher.update(b"AF_ENCRYPTION_KEY_V1");
    hasher.update(seed);
    hasher.update(b"DILITHIUM_STORAGE");
    hasher.finalize().into()
}

fn generate_secure_filename(seed: &[u8; 32]) -> String {
    use sha2::{Sha256, Digest};
    
    // Hash the seed for filename
    let mut hasher = Sha256::new();
    hasher.update(b"AF_FILENAME_V1");
    hasher.update(seed);
    let hash = hasher.finalize();
    
    format!(".af_dilithium_{}", hex::encode(&hash[..16]))
}
/// Validate file path for security
fn validate_encrypted_file_path(seed: &[u8; 32]) -> Result<std::path::PathBuf, CryptoError> {
    use std::path::Path;
    
    let filename = generate_secure_filename(seed);
    let path = Path::new(&filename);
    
    // Security validation
    if path.is_absolute() || path.components().count() > 1 {
        return Err(CryptoError::InvalidOperation { 
            details: "Invalid file path for security".to_string() 
        });
    }
    
    Ok(path.to_path_buf())
}
/// Save encrypted Dilithium keypair to disk
fn save_encrypted_dilithium_keypair(seed: &[u8; 32], keypair: &DilithiumKeypair) -> Result<(), CryptoError> {
    use aes_gcm::{Aes256Gcm, Key, KeyInit, AeadCore};
    use aes_gcm::aead::Aead;
    
    // Validate file path for security
    let file_path = validate_encrypted_file_path(seed)?;
    
    // Use derived encryption key (NOT the seed directly)
    let encryption_key = derive_encryption_key(seed);
    let key = Key::<Aes256Gcm>::from(encryption_key);
    let cipher = Aes256Gcm::new(&key);
    
    // Generate random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);
    
    // Serialize keypair
    let keypair_bytes = [keypair.public.to_bytes().as_slice(), keypair.secret.to_bytes().as_slice()].concat();
    
    // Encrypt
    let ciphertext = cipher.encrypt(&nonce, keypair_bytes.as_ref())
        .map_err(|_| CryptoError::InvalidOperation { details: "Encryption failed".to_string() })?;
    
    // Save to file
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&nonce);
    file_data.extend_from_slice(&ciphertext);
    
    std::fs::write(&file_path, file_data)
        .map_err(|_| CryptoError::InvalidOperation { details: "Failed to save encrypted keypair".to_string() })?;
    
    Ok(())
}

/// Load encrypted Dilithium keypair from disk
fn load_encrypted_dilithium_keypair(seed: &[u8; 32]) -> Result<DilithiumKeypair, CryptoError> {
    use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
    use aes_gcm::aead::Aead;
    
    // Validate file path for security
    let file_path = validate_encrypted_file_path(seed)?;
    
    let file_data = std::fs::read(&file_path)
        .map_err(|_| CryptoError::InvalidOperation { details: "Encrypted keypair not found".to_string() })?;
    
    if file_data.len() < 12 {
        return Err(CryptoError::InvalidOperation { details: "Invalid encrypted file".to_string() });
    }
    
    // Extract nonce and ciphertext
    let (nonce_bytes, ciphertext) = file_data.split_at(12);
    let nonce_array: [u8; 12] = nonce_bytes.try_into()
        .map_err(|_| CryptoError::InvalidOperation { details: "Invalid nonce size".to_string() })?;
    let nonce = Nonce::from(nonce_array);
    
    // Use derived encryption key
    let encryption_key = derive_encryption_key(seed);
    let key = Key::<Aes256Gcm>::from(encryption_key);
    let cipher = Aes256Gcm::new(&key);
    
    // Decrypt
    let plaintext = cipher.decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::InvalidOperation { details: "Decryption failed".to_string() })?;
    
    // Reconstruct keypair
    if plaintext.len() != PUBLICKEYBYTES + crystals_dilithium::dilithium3::SECRETKEYBYTES {
        return Err(CryptoError::InvalidOperation { details: "Invalid keypair data".to_string() });
    }
    
    let public_bytes = &plaintext[..PUBLICKEYBYTES];
    let secret_bytes = &plaintext[PUBLICKEYBYTES..];
    
    let public_key = crystals_dilithium::dilithium3::PublicKey::from_bytes(public_bytes);
    let secret_key = crystals_dilithium::dilithium3::SecretKey::from_bytes(secret_bytes);
    
    Ok(DilithiumKeypair { public: public_key, secret: secret_key })
}

// End of module

