#!/bin/bash

# test-bitbucket-integration.sh
# Verifies that Bitbucket integration components are correctly configured in the local environment.

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "🔍 Verifying Bitbucket Integration Configuration..."

# 1. Check for Bitbucket Environment Variables in .env (if it exists)
echo -e "\n1. Checking Environment Variables..."
if [ -f "packages/web/.env" ]; then
    if grep -q "BITBUCKET_CLIENT_ID" packages/web/.env && grep -q "BITBUCKET_CLIENT_SECRET" packages/web/.env; then
        echo -e "${GREEN}✅ Bitbucket OAuth credentials found in packages/web/.env${NC}"
    else
        echo -e "${RED}❌ Missing BITBUCKET_CLIENT_ID or BITBUCKET_CLIENT_SECRET in packages/web/.env${NC}"
    fi
else
    echo -e "${RED}⚠️  packages/web/.env file not found. Ensure environment variables are set in Vercel/Cloudflare.${NC}"
fi

# 2. Check for Bitbucket Bot Credentials (simulated check)
# These are typically in terraform.tfvars or Cloudflare secrets, so we can't easily check them directly.
# But we can check if the code references them.
echo -e "\n2. Verifying Codebase for Bitbucket Support..."

# Check if router.ts handles X-VCS-Provider
if grep -q "X-VCS-Provider" packages/control-plane/src/router.ts; then
    echo -e "${GREEN}✅ Control Plane router supports X-VCS-Provider header${NC}"
else
    echo -e "${RED}❌ Control Plane router missing X-VCS-Provider support${NC}"
fi

# Check if bridge.py handles Bitbucket URL
if grep -q "bitbucket.org" packages/modal-infra/src/sandbox/bridge.py; then
    echo -e "${GREEN}✅ Sandbox bridge supports Bitbucket URLs${NC}"
else
    echo -e "${RED}❌ Sandbox bridge missing Bitbucket URL support${NC}"
fi

# Check if entrypoint.py handles Bitbucket clone
if grep -q "bitbucket.org" packages/modal-infra/src/sandbox/entrypoint.py; then
    echo -e "${GREEN}✅ Sandbox entrypoint supports Bitbucket clone${NC}"
else
    echo -e "${RED}❌ Sandbox entrypoint missing Bitbucket clone support${NC}"
fi

# 3. Simulate Repo Listing Request (curl)
# This requires the control plane to be running locally via `npm run dev`
echo -e "\n3. Testing Local API (Optional)..."
echo "To test the repository listing API locally:"
echo "1. Start the control plane: npm run dev -w @open-inspect/control-plane"
echo "2. Run this curl command (replace TOKEN with a valid Bitbucket OAuth token):"
echo ""
echo "   curl -X GET \"http://localhost:8787/repos\" \\"
echo "     -H \"X-VCS-Provider: bitbucket\" \\"
echo "     -H \"X-User-Token: YOUR_BITBUCKET_TOKEN\""
echo ""

# 4. Terraform Configuration Check
echo -e "\n4. Checking Terraform Configuration..."
if [ -f "terraform/environments/production/terraform.tfvars" ]; then
    if grep -q "bitbucket_bot_username" terraform/environments/production/terraform.tfvars; then
        echo -e "${GREEN}✅ Bitbucket bot credentials found in terraform.tfvars${NC}"
    else
        echo -e "${RED}⚠️  Bitbucket bot credentials missing from terraform.tfvars${NC}"
    fi
else
    echo -e "${RED}⚠️  terraform.tfvars not found. Ensure variables are set for deployment.${NC}"
fi

echo -e "\n---------------------------------------------------"
echo -e "🎉 Verification Complete!"
echo -e "Next steps:"
echo -e "1. Add BITBUCKET_CLIENT_ID and BITBUCKET_CLIENT_SECRET to packages/web/.env.local"
echo -e "2. Add BITBUCKET_BOT_USERNAME and BITBUCKET_BOT_APP_PASSWORD to Cloudflare secrets"
echo -e "3. Deploy changes using Terraform"
