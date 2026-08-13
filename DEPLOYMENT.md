# Verifiable Wallet Deployment

## Canonical Runtime

- service repo: `services/verifiable-wallet-service`
- runtime path: `worker`
- production compose: `worker/phala-compose.yaml`
- public endpoint: `https://vault.mysterygift.fun`

## Deploy

```bash
cd /Users/area/repos/mystery-gift/services/verifiable-wallet-service/worker
phala deploy --compose phala-compose.yaml -e .env
```

## Required Environment

- `WALLET_SERVICE_SECRET`
- `REDIS_URL` — required in production for money routes (rate limits + USDC daily cap); without it those routes return 503

Common production settings:

- `PHALA_TEE=true`
- `HELIUS_RPC_URL`
- `ALCHEMY_RPC_URL`
- `SOLANA_RPC_URL`
- `BASE_RPC_URL`
- `BASE_NETWORK`
- `WALLET_LABELS_PATH`
- `REDIS_URL`
- `MAGICEDEN_ALLOWED_PROGRAM_IDS`

## Verify

```bash
curl -sS https://vault.mysterygift.fun/health
```
