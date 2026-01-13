#!/bin/bash
# ===========================================
# Quick Deploy to Phala Cloud
# ===========================================
# This is a simplified interactive deployment script.
# Run: ./scripts/quick-deploy.sh

set -e

cd "$(dirname "$0")/.."

echo ""
echo "==================================================="
echo "  Mystery Gift TEE Wallet - Quick Deploy"
echo "==================================================="
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v docker &>/dev/null; then
	echo "ERROR: Docker is not installed."
	exit 1
fi

if ! docker info &>/dev/null 2>&1; then
	echo "ERROR: Docker is not running. Please start Docker."
	exit 1
fi

# Check Docker Hub login and get username
DOCKER_USERNAME=${DOCKER_USERNAME:-""}

if [ -z "$DOCKER_USERNAME" ]; then
	# Method 1: Try docker system info
	DOCKER_USERNAME=$(docker system info 2>/dev/null | grep -i "username" | awk '{print $2}' | head -1)

	# Method 2: Try docker info
	if [ -z "$DOCKER_USERNAME" ]; then
		DOCKER_USERNAME=$(docker info 2>&1 | grep -i "username" | awk '{print $2}' | head -1)
	fi

	# Method 3: Check docker config.json for auth
	if [ -z "$DOCKER_USERNAME" ]; then
		if [ -f ~/.docker/config.json ]; then
			# Try to get username from auths section (it's base64 encoded as user:pass)
			AUTH=$(cat ~/.docker/config.json | python3 -c "import sys,json; d=json.load(sys.stdin); auths=d.get('auths',{}); hub=auths.get('https://index.docker.io/v1/',{}); print(hub.get('auth',''))" 2>/dev/null || echo "")
			if [ -n "$AUTH" ]; then
				DOCKER_USERNAME=$(echo "$AUTH" | base64 -d 2>/dev/null | cut -d: -f1 || echo "")
			fi
		fi
	fi
fi

# If we still don't have a username, we need to login
if [ -z "$DOCKER_USERNAME" ]; then
	echo ""
	echo "You need to log into Docker Hub first."
	echo "Running: docker login"
	echo ""
	docker login

	# Try again after login
	DOCKER_USERNAME=$(docker info 2>&1 | grep -i "username" | awk '{print $2}' | head -1)
fi

# Final check - ask user if still empty
if [ -z "$DOCKER_USERNAME" ]; then
	echo ""
	echo "Could not auto-detect Docker Hub username."
	while [ -z "$DOCKER_USERNAME" ]; do
		read -p "Enter your Docker Hub username: " DOCKER_USERNAME
		if [ -z "$DOCKER_USERNAME" ]; then
			echo "Username cannot be empty. Please try again."
		fi
	done
fi

echo "Docker Hub username: $DOCKER_USERNAME"

# Check Phala login
echo ""
echo "Checking Phala Cloud login..."
PHALA_STATUS=$(npx phala status 2>&1 || echo "not logged in")
if ! echo "$PHALA_STATUS" | grep -qi "authenticated\\|logged in\\|API key\\|Welcome"; then
	echo ""
	echo "You need to log into Phala Cloud first."
	echo "Running: npx phala login"
	echo ""
	npx phala login
fi

echo ""
echo "==================================================="
echo "  Configuration"
echo "==================================================="
echo ""

# Load from .env file if it exists (non-interactive mode)
if [ -f .env ]; then
	echo "Found .env file, loading configuration..."
	set -a
	source .env
	set +a
	echo "Loaded configuration from .env ✓"
	echo ""
fi

# Load package.json version
PACKAGE_VERSION=$(cat package.json | grep '"version"' | cut -d'"' -f4)

# Set defaults
IMAGE_NAME="${DOCKER_USERNAME}/verifiable-wallet-service:v${PACKAGE_VERSION}"
CVM_NAME="verifiable-wallet-service"
APP_VERSION="$PACKAGE_VERSION"

echo "Docker Image: $IMAGE_NAME"
echo "CVM Name: $CVM_NAME"
echo ""

# Service secret - use existing or generate fresh
if [ -z "$WALLET_SERVICE_SECRET" ]; then
	echo ""
	echo "Generating new service secret..."
	WALLET_SERVICE_SECRET=$(openssl rand -hex 32)
	echo "New service secret generated ✓"
	NEW_SECRET_GENERATED=true
else
	echo "Using existing WALLET_SERVICE_SECRET from .env ✓"
	NEW_SECRET_GENERATED=false
fi

echo ""
echo "==================================================="
echo "  Building Docker Image"
echo "==================================================="
echo ""

# Build TypeScript
echo "Compiling TypeScript..."
npm run build

# Build Docker image for linux/amd64 (required for Phala TEE)
echo ""
echo "Building Docker image: $IMAGE_NAME (linux/amd64)"
echo "Note: Phala TEE runs on x86_64/amd64 architecture"

# Use buildx to build and push for amd64 platform
docker buildx create --name phala-builder --use 2>/dev/null || docker buildx use phala-builder 2>/dev/null || true
docker buildx build --platform linux/amd64 -t "$IMAGE_NAME" --push .

echo ""
echo "Image built and pushed to Docker Hub!"

echo ""
echo "==================================================="
echo "  Preparing Phala Deployment"
echo "==================================================="
echo ""

# Update the compose file with the correct image
if [[ "$OSTYPE" == "darwin"* ]]; then
	# macOS
	sed -i '' "s|image:.*|image: $IMAGE_NAME|g" phala-compose.yaml
else
	# Linux
	sed -i "s|image:.*|image: $IMAGE_NAME|g" phala-compose.yaml
fi

echo "Updated phala-compose.yaml with image: $IMAGE_NAME"

# Create .env file for phala deploy
cat >.env.deploy <<EOF
WALLET_SERVICE_SECRET=$WALLET_SERVICE_SECRET
PHALA_TEE=true
PORT=3000
NODE_ENV=production
APP_VERSION=$APP_VERSION
SOLANA_RPC_URL=${SOLANA_RPC_URL:-https://api.devnet.solana.com}
WALLET_LABELS_PATH=/app/data/wallet-labels.json
EOF

echo "Created .env.deploy with environment variables"

echo ""
echo "==================================================="
echo "  Deploying to Phala Cloud"
echo "==================================================="
echo ""

echo "Deploying CVM: $CVM_NAME"
echo ""

# Use the phala deploy command with all options
npx phala deploy \
	--name "$CVM_NAME" \
	--compose ./phala-compose.yaml \
	-e .env.deploy \
	--vcpu 1 \
	--memory 2G \
	--disk-size 20G

# Clean up temp file
rm -f .env.deploy

echo ""
echo "==================================================="
echo "  Deployment Complete!"
echo "==================================================="
echo ""
echo "Getting your CVM details..."
echo ""
npx phala cvms list 2>/dev/null || echo "(run 'npx phala cvms list' to see your CVMs)"

echo ""
echo "Next steps:"
echo "1. Run 'npx phala cvms list' to get your App ID"
echo "2. Your endpoint will be: https://[app-id]-3000.dstack-pha-prod5.phala.network"
echo "3. Test your endpoint: curl https://[app-id]-3000.dstack-pha-prod5.phala.network/health"
echo ""
echo "4. Update apps/marketplace/api/.env with:"
echo "   TEE_VAULT_ENDPOINT=https://[app-id]-3000.dstack-pha-prod5.phala.network"

if [ "$NEW_SECRET_GENERATED" = true ]; then
	echo "   TEE_VAULT_API_KEY=${WALLET_SERVICE_SECRET}"
	echo ""
	echo "Your Service Secret (keep this secret!):"
	echo "  ${WALLET_SERVICE_SECRET}"
	echo ""
	echo "IMPORTANT: This secret was just generated. Save it now!"
	echo "           It will not be shown again."
else
	echo "   TEE_VAULT_API_KEY=<use your existing secret from .env>"
	echo ""
	echo "Using existing service secret from your .env file."
fi
echo ""
