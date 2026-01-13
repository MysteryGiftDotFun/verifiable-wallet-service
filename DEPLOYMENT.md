# Verified Wallet Service Deployment Guide

## Prerequisites

- Docker installed
- Access to Phala Cloud dashboard
- Docker registry access (e.g., Docker Hub account)
- Service secrets configured

## Environment Variables

Create a `.env` file for Phala deployment:

```env
PORT=3000
NODE_ENV=production
WALLET_SERVICE_SECRET=<your-secure-secret-key>
PHALA_TEE=true
```

**Important:** Replace `<your-secure-secret-key>` with a securely generated secret. This secret will be used by the marketplace API to authenticate with the wallet service.

## Build and Push Docker Image

```bash
# Navigate to the service directory
cd services/verifiable-wallet-service/worker

# Build the Docker image
docker build -t <your-dockerhub-username>/verifiable-wallet-service:v0.0.2 .

# Login to Docker Hub (if not already logged in)
docker login

# Push the image
docker push <your-dockerhub-username>/verifiable-wallet-service:v0.0.2
```

## Deploy to Phala Cloud

### Option 1: Using Phala Dashboard

1. Go to https://dstack.phala.network
2. Click "Create New Application"
3. Choose "Docker Compose" deployment
4. Upload the `phala-compose.yaml` file
5. Configure environment variables in the dashboard:
   - `WALLET_SERVICE_SECRET`: Your secure secret key
   - `PHALA_TEE`: Set to `true`
   - `PORT`: `3000`
   - `NODE_ENV`: `production`
6. Update the image name in phala-compose.yaml to match your pushed image
7. Deploy the application

### Option 2: Using Phala CLI

```bash
# Install Phala CLI
npm install -g @phala/fn

# Login to Phala
phala-fn login

# Deploy the service
phala-fn deploy --compose phala-compose.yaml
```

## Configure Custom Domain (Optional)

If you want to use a custom domain like `wallet.mysterygift.fun`:

1. In Phala Cloud dashboard, go to your application settings
2. Click "Custom Domain"
3. Add your domain: `wallet.mysterygift.fun`
4. Phala will provide CNAME and TXT records
5. Add these records to your DNS provider:
   - CNAME: `wallet.mysterygift.fun` → `*.dstack-pha-prod5.phala.network`
   - TXT: `_dstack-app-address.wallet.mysterygift.fun` → `<app-id>:3000`
   - TXT: `_tapp-address.wallet.mysterygift.fun` → `<app-id>:3000`
6. Wait for DNS propagation (5-30 minutes)
7. Verify in Phala dashboard that the domain is verified

## Update Marketplace API Configuration

After deployment, update the marketplace API environment variables:

### In `apps/marketplace/api/.env`:

```env
TEE_VAULT_ENDPOINT=https://wallet.mysterygift.fun
TEE_VAULT_API_KEY=<your-secure-secret-key>
```

Or if using the default Phala URL:

```env
TEE_VAULT_ENDPOINT=https://<your-app-id>.dstack.phala.network:3000
TEE_VAULT_API_KEY=<your-secure-secret-key>
```

## Verification

### Test the health endpoint:

```bash
curl https://wallet.mysterygift.fun/health
```

Expected response:

```json
{
  "status": "ok",
  "service": "verifiable-wallet-service",
  "tee": "active"
}
```

### Test the public key endpoint (with auth):

```bash
curl -H "Authorization: Bearer <your-secret>" https://wallet.mysterygift.fun/public-key
```

Expected response:

```json
{
  "publicKey": "<base58-encoded-public-key>"
}
```

### Test full integration:

1. Start marketplace: `pnpm dev:marketplace`
2. Navigate to http://localhost:5558
3. Click on a pack (e.g., Rookie Pack)
4. Check that payment address loads correctly
5. Attempt a purchase (will require real NFTs in vault)

## Troubleshooting

### Service not responding

- Check Phala Cloud logs in the dashboard
- Verify environment variables are set correctly
- Ensure Docker image was pushed successfully

### "Unauthorized" errors

- Verify `WALLET_SERVICE_SECRET` matches in both:
  - Phala deployment environment variables
  - Marketplace API `.env` file (`TEE_VAULT_API_KEY`)

### TEE derivation errors

- Ensure `PHALA_TEE=true` is set in the environment
- Check Phala Cloud logs for TEE initialization errors
- Verify the Phala dstack daemon is running (automatic in Phala Cloud)

### DNS issues

- Use `dig` or `nslookup` to verify DNS records propagated:
  ```bash
  dig wallet.mysterygift.fun
  dig TXT _dstack-app-address.wallet.mysterygift.fun
  ```
- Wait up to 30 minutes for full DNS propagation
- Try accessing via the direct Phala URL first to isolate DNS issues

## Security Notes

1. **Never commit `.env` files** with real secrets to git
2. **Rotate secrets regularly** - especially `WALLET_SERVICE_SECRET`
3. **Use different secrets** for development and production
4. **Monitor logs** for unauthorized access attempts
5. **Keep Docker image updated** with security patches

## Maintenance

### Update the service:

```bash
# Make code changes
# Build new image
docker build -t <username>/verifiable-wallet-service:v0.0.3 .
docker push <username>/verifiable-wallet-service:v0.0.3

# Update phala-compose.yaml with new version
# Redeploy via Phala dashboard or CLI
```

### View logs:

- In Phala Cloud dashboard, go to your application
- Click "Logs" tab to view real-time logs
- Filter by severity or search for specific errors

## FAQ

**Q: Can I use this service locally for testing?**
A: Yes, run `pnpm install && pnpm start` in the worker directory. It will use simulated TEE mode with deterministic keys.

**Q: What happens if the service goes down?**
A: NFT transfers will fail. The marketplace API will return an error to users. Implement retry logic and monitoring.

**Q: How do I backup the vault keys?**
A: Keys are derived from Phala's TEE environment. They cannot and should not be exported. The derivation is deterministic, so redeploying with the same configuration recreates the same keys.

**Q: Can I use multiple instances for high availability?**
A: Yes, but all instances must use the same key derivation ID to produce the same wallet address. Coordinate through Phala's load balancing features.
