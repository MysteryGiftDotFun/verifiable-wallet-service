# Verifiable Wallet Service Deployment Guide

## Automated Deployment (GitLab CI/CD)

The service is configured to automatically deploy to Phala Cloud on every push to `main` or `development`.

### Prerequisites

1.  **First Manual Deployment**: You must deploy manually once to generate the App ID (Bootstrap).

    - Run `cd worker && ./scripts/quick-deploy.sh`
    - Note the `App ID` (e.g., `app_...`) and `Service Secret`.
    - **Current App ID**: `app_bffd0c88fe51064a95148f90cca3c3733e4a9177` (Deployed Jan 12 2026)

2.  **GitLab Variables**: Set the following in **Settings > CI/CD > Variables**:
    - `DOCKER_USERNAME`: Docker Hub username
    - `DOCKER_PASSWORD`: Docker Hub password/token
    - `PHALA_CLOUD_KEY`: Phala Cloud API Token
    - `PHALA_APP_ID`: The App ID from step 1.

### Branching Strategy

- **`main`**: Deploys to the production CVM (`PHALA_APP_ID`).
- **`development`**: Also deploys to the _same_ CVM (as configured).
  - _Note_: To separate environments, create a second CVM and use `PHALA_APP_ID_DEV` in `.gitlab-ci.yml`.

## Manual Deployment

```bash
cd worker
./scripts/quick-deploy.sh
```

## Configuration

Update `apps/marketplace/api/.env` with your endpoint:

```env
TEE_VAULT_ENDPOINT=https://[app-id]-3000.dstack-pha-prod5.phala.network
TEE_VAULT_API_KEY=[your-service-secret]
```

## Environment Variables

For manual deployment using `.env`:

```env
PORT=3000
NODE_ENV=production
WALLET_SERVICE_SECRET=<your-secure-secret-key>
PHALA_TEE=true
```

## Verification

### Test the health endpoint:

```bash
curl https://[app-id]-3000.dstack-pha-prod5.phala.network/health
```

Expected response:

```json
{
  "status": "ok",
  "service": "verifiable-wallet-service",
  "tee": "active"
}
```
