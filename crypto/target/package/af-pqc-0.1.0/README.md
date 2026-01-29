# AF-PQC: Authority Fabric Post-Quantum Cryptography

Production-ready post-quantum cryptographic framework with hybrid Dilithium3 + Ed25519 signatures.

## Features

- **Post-Quantum Security**: Dilithium3 (NIST standardized) + Ed25519 hybrid signatures
- **Deterministic Key Generation**: Reproducible keypairs from seeds
- **Encrypted Key Storage**: Secure Dilithium keypair caching
- **Enterprise CLI**: Professional command-line interface
- **Optional Witness Integration**: Constitutional compliance features (feature flag)

## Quick Start

```toml
[dependencies]
af-pqc = "0.1.0"
```

### Basic Usage

```rust
use af_pqc::{PrivateKey, generate_key_from_seed};

// Generate from seed
let seed = [0u8; 32]; // Use secure random seed
let (private_key, public_key) = generate_key_from_seed(&seed)?;

// Sign and verify
let message = b"Hello, post-quantum world!";
let signature = private_key.sign(message)?;
public_key.verify(message, &signature)?;
```

### CLI Usage

```bash
# Generate secure seed
af-cli generate-seed

# Generate keypair
af-cli keygen -P pubkey.json -s <seed>

# Sign message
af-cli sign --seed <seed> -m "message" -o signature.json

# Verify signature
af-cli verify -P pubkey.json -s signature.json -m "message"
```

## Security Features

- **Quantum-Resistant**: Dilithium3 lattice-based cryptography
- **Hybrid Security**: Ed25519 for current threat model
- **Key Usage Limits**: Automatic key rotation triggers
- **Secure Storage**: AES-GCM encrypted key caching
- **Memory Safety**: Zeroization of sensitive data

## Optional Features

### Witness Integration

```toml
af-pqc = { version = "0.1.0", features = ["witness-integration"] }
```

Enables constitutional compliance and witness binding for Authority Fabric integration.

## License

MIT OR Apache-2.0
