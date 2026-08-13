# Verifiable Wallet Service

This service provides the live Mystery Gift vault and signing runtime at `https://vault.mysterygift.fun`.

## Current Scope

- Phala TEE-backed signing
- Solana and Base wallet operations
- internal transfer and marketplace validation helpers
- bearer-token protected service-to-service API

Production money routes (`/transfer-usdc`, `/transfer-nft`, `/sign-transaction`) require `REDIS_URL` and fail closed with 503 if Redis is unavailable.

See [DEPLOYMENT.md](DEPLOYMENT.md) for the current deployment contract.
