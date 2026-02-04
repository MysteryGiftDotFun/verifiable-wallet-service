# Changelog

All notable changes to Verifiable Wallet Service.

## [0.1.0-BETA] - 2026-01-21

### Initial Release

**Wallet Management:**

- TEE-protected wallet generation
- Multi-wallet support with labels
- Secure key derivation
- Wallet inventory tracking

**Transaction Features:**

- SOL transfers
- SPL token transfers
- NFT transfers with ATA creation
- Transaction signing in TEE

**API Endpoints:**

- `GET /wallets` - List managed wallets
- `POST /wallets` - Create new wallet
- `GET /wallets/:label` - Get wallet by label
- `POST /transfer` - Execute transfer
- `GET /balance/:address` - Check balance
- `GET /health` - Health check

**TEE Integration:**

- Intel TDX hardware-backed key storage
- Phala dStack SDK for secure execution
- Remote attestation for verification
- Derived keys never leave enclave

**Security:**

- API key authentication
- Rate limiting
- Audit logging
- No plaintext key export

**Multi-RPC Support:**

- Helius RPC (primary)
- Alchemy RPC (fallback)
- Public Solana RPC (backup)

**Deployment:**

- Docker support for Phala Cloud
- Persistent wallet data volume
- Multi-environment (mainnet/devnet)
