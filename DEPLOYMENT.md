# Deployment Guide

This guide walks through deploying the Euno capability governance system to Azure.

## Prerequisites

- Azure CLI installed and configured
- Azure subscription with appropriate permissions
- Docker installed (for containerization)
- kubectl configured for AKS (if using Kubernetes)

## Step 1: Azure Resource Setup

### Create Resource Group

```bash
az group create \
  --name euno-rg \
  --location eastus
```

### Create Azure Key Vault

```bash
# Create Key Vault
az keyvault create \
  --name euno-keyvault \
  --resource-group euno-rg \
  --location eastus

# Generate signing key
az keyvault key create \
  --vault-name euno-keyvault \
  --name capability-signing-key \
  --kty RSA \
  --size 2048

# Get Key Vault URL
az keyvault show \
  --name euno-keyvault \
  --query properties.vaultUri \
  --output tsv
```

### Register Azure AD Application

```bash
# Create app registration
az ad app create \
  --display-name "Euno Capability Issuer" \
  --sign-in-audience AzureADMyOrg

# Get application ID
az ad app list \
  --display-name "Euno Capability Issuer" \
  --query [0].appId \
  --output tsv

# Create service principal
az ad sp create --id <APP_ID>

# Grant Key Vault permissions
az keyvault set-policy \
  --name euno-keyvault \
  --spn <APP_ID> \
  --key-permissions sign verify get

# Create client secret
az ad app credential reset \
  --id <APP_ID> \
  --append
```

## Step 2: Container Registry

```bash
# Create Azure Container Registry
az acr create \
  --name eunoacr \
  --resource-group euno-rg \
  --sku Basic

# Login to ACR
az acr login --name eunoacr

# Get ACR login server
az acr show \
  --name eunoacr \
  --query loginServer \
  --output tsv
```

## Step 3: Build and Push Docker Images

### Capability Issuer

Create `packages/capability-issuer/Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY packages/common/package*.json ./packages/common/
COPY packages/capability-issuer/package*.json ./packages/capability-issuer/

# Install dependencies
RUN npm ci --workspace=@euno/common --workspace=@euno/capability-issuer

# Copy source code
COPY packages/common ./packages/common
COPY packages/capability-issuer ./packages/capability-issuer
COPY tsconfig.json ./

# Build
RUN npm run build --workspace=@euno/common
RUN npm run build --workspace=@euno/capability-issuer

# Set working directory to capability-issuer
WORKDIR /app/packages/capability-issuer

# Expose port
EXPOSE 3001

# Start service
CMD ["node", "dist/index.js"]
```

Build and push:

```bash
# Build capability issuer
docker build -t eunoacr.azurecr.io/capability-issuer:v1.0.0 -f packages/capability-issuer/Dockerfile .
docker push eunoacr.azurecr.io/capability-issuer:v1.0.0

# Build tool gateway
docker build -t eunoacr.azurecr.io/tool-gateway:v1.0.0 -f packages/tool-gateway/Dockerfile .
docker push eunoacr.azurecr.io/tool-gateway:v1.0.0
```

### Tool Gateway

Create `packages/tool-gateway/Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY packages/common/package*.json ./packages/common/
COPY packages/tool-gateway/package*.json ./packages/tool-gateway/

# Install dependencies
RUN npm ci --workspace=@euno/common --workspace=@euno/tool-gateway

# Copy source code
COPY packages/common ./packages/common
COPY packages/tool-gateway ./packages/tool-gateway
COPY tsconfig.json ./

# Build
RUN npm run build --workspace=@euno/common
RUN npm run build --workspace=@euno/tool-gateway

# Set working directory to tool-gateway
WORKDIR /app/packages/tool-gateway

# Expose port
EXPOSE 3002

# Start service
CMD ["node", "dist/index.js"]
```

## Step 4: Deploy to Azure Container Instances

### Deploy Capability Issuer

```bash
az container create \
  --name capability-issuer \
  --resource-group euno-rg \
  --image eunoacr.azurecr.io/capability-issuer:v1.0.0 \
  --registry-login-server eunoacr.azurecr.io \
  --registry-username <ACR_USERNAME> \
  --registry-password <ACR_PASSWORD> \
  --dns-name-label euno-issuer \
  --ports 3001 \
  --environment-variables \
    NODE_ENV=production \
    PORT=3001 \
    AZURE_KEYVAULT_URL=<KEYVAULT_URL> \
    AZURE_KEYVAULT_KEY_NAME=capability-signing-key \
    AZURE_AD_TENANT_ID=<TENANT_ID> \
    AZURE_AD_CLIENT_ID=<CLIENT_ID> \
    ISSUER_DID=did:web:yourdomain.com \
    DEFAULT_TOKEN_TTL=900 \
  --secure-environment-variables \
    AZURE_CLIENT_SECRET=<CLIENT_SECRET> \
  --cpu 1 \
  --memory 1.5
```

### Deploy Tool Gateway

```bash
az container create \
  --name tool-gateway \
  --resource-group euno-rg \
  --image eunoacr.azurecr.io/tool-gateway:v1.0.0 \
  --registry-login-server eunoacr.azurecr.io \
  --registry-username <ACR_USERNAME> \
  --registry-password <ACR_PASSWORD> \
  --dns-name-label euno-gateway \
  --ports 3002 \
  --environment-variables \
    NODE_ENV=production \
    PORT=3002 \
    ISSUER_PUBLIC_KEY_URL=http://euno-issuer.eastus.azurecontainer.io:3001/api/v1/public-key \
    BACKEND_SERVICE_URL=<BACKEND_URL> \
    POLICY_VERSION=1.0.0 \
  --secure-environment-variables \
    ADMIN_API_KEY=<SECURE_RANDOM_KEY> \
  --cpu 1 \
  --memory 1.5
```

## Step 5: Deploy to Azure Kubernetes Service (AKS)

### Create AKS Cluster

```bash
az aks create \
  --resource-group euno-rg \
  --name euno-aks \
  --node-count 2 \
  --enable-managed-identity \
  --attach-acr eunoacr \
  --generate-ssh-keys

# Get credentials
az aks get-credentials \
  --resource-group euno-rg \
  --name euno-aks
```

### Create Kubernetes Secrets

```bash
kubectl create secret generic issuer-secrets \
  --from-literal=azure-client-secret=<CLIENT_SECRET>

kubectl create secret generic gateway-secrets \
  --from-literal=admin-api-key=<SECURE_RANDOM_KEY>
```

### Deploy Capability Issuer

Create `k8s/capability-issuer.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: capability-issuer
spec:
  replicas: 2
  selector:
    matchLabels:
      app: capability-issuer
  template:
    metadata:
      labels:
        app: capability-issuer
    spec:
      containers:
      - name: capability-issuer
        image: eunoacr.azurecr.io/capability-issuer:v1.0.0
        ports:
        - containerPort: 3001
        env:
        - name: NODE_ENV
          value: "production"
        - name: PORT
          value: "3001"
        - name: AZURE_KEYVAULT_URL
          value: "<KEYVAULT_URL>"
        - name: AZURE_KEYVAULT_KEY_NAME
          value: "capability-signing-key"
        - name: AZURE_AD_TENANT_ID
          value: "<TENANT_ID>"
        - name: AZURE_AD_CLIENT_ID
          value: "<CLIENT_ID>"
        - name: ISSUER_DID
          value: "did:web:yourdomain.com"
        - name: DEFAULT_TOKEN_TTL
          value: "900"
        - name: AZURE_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: issuer-secrets
              key: azure-client-secret
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: capability-issuer
spec:
  type: LoadBalancer
  ports:
  - port: 3001
    targetPort: 3001
  selector:
    app: capability-issuer
```

Apply:

```bash
kubectl apply -f k8s/capability-issuer.yaml
```

### Deploy Tool Gateway

Create `k8s/tool-gateway.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tool-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tool-gateway
  template:
    metadata:
      labels:
        app: tool-gateway
    spec:
      containers:
      - name: tool-gateway
        image: eunoacr.azurecr.io/tool-gateway:v1.0.0
        ports:
        - containerPort: 3002
        env:
        - name: NODE_ENV
          value: "production"
        - name: PORT
          value: "3002"
        - name: ISSUER_PUBLIC_KEY_URL
          value: "http://capability-issuer:3001/api/v1/public-key"
        - name: BACKEND_SERVICE_URL
          value: "<BACKEND_URL>"
        - name: POLICY_VERSION
          value: "1.0.0"
        - name: ADMIN_API_KEY
          valueFrom:
            secretKeyRef:
              name: gateway-secrets
              key: admin-api-key
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: tool-gateway
spec:
  type: LoadBalancer
  ports:
  - port: 3002
    targetPort: 3002
  selector:
    app: tool-gateway
```

Apply:

```bash
kubectl apply -f k8s/tool-gateway.yaml
```

## Step 6: Configure Networking

### Network Security with NetworkPolicy

Create `k8s/network-policy.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-network-policy
spec:
  podSelector:
    matchLabels:
      role: agent
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: tool-gateway
    ports:
    - protocol: TCP
      port: 3002
  # Block all other egress traffic
```

## Step 7: Monitoring & Observability

### Azure Monitor Integration

```bash
# Enable Container Insights
az aks enable-addons \
  --resource-group euno-rg \
  --name euno-aks \
  --addons monitoring
```

### Application Insights

```bash
# Create Application Insights
az monitor app-insights component create \
  --app euno-insights \
  --location eastus \
  --resource-group euno-rg

# Get instrumentation key
az monitor app-insights component show \
  --app euno-insights \
  --resource-group euno-rg \
  --query instrumentationKey \
  --output tsv
```

Add to deployment environment variables:
```yaml
- name: APPLICATIONINSIGHTS_CONNECTION_STRING
  value: "InstrumentationKey=<KEY>"
```

## Step 8: Production Checklist

- [ ] Azure Key Vault configured with HSM-backed keys
- [ ] Azure AD application registered with proper permissions
- [ ] Managed identities configured for pods
- [ ] Network policies restrict agent egress
- [ ] HTTPS/TLS configured on all endpoints
- [ ] Admin API key set and secured
- [ ] Container images scanned for vulnerabilities
- [ ] Resource limits set on all pods
- [ ] Horizontal Pod Autoscaling configured
- [ ] Azure Monitor / Application Insights enabled
- [ ] Alert rules configured for critical conditions
- [ ] Backup and disaster recovery plan in place
- [ ] Security audit completed

## Troubleshooting

### Check Pod Logs

```bash
kubectl logs -l app=capability-issuer --tail=100
kubectl logs -l app=tool-gateway --tail=100
```

### Check Service Status

```bash
kubectl get pods
kubectl get services
kubectl describe pod <POD_NAME>
```

### Test Connectivity

```bash
# From within the cluster
kubectl run -it --rm debug --image=alpine --restart=Never -- sh
wget -O- http://capability-issuer:3001/health
```

## Security Considerations

1. **Use Managed Identities**: Enable managed identities for AKS pods to avoid storing credentials
2. **Rotate Keys Regularly**: Set up automated key rotation in Azure Key Vault
3. **Monitor Admin API**: Track all admin API calls and set alerts for suspicious activity
4. **Rate Limiting**: Configure rate limits on API endpoints
5. **DDoS Protection**: Enable Azure DDoS Protection on public endpoints
6. **Regular Updates**: Keep container images and dependencies up to date

## Cost Optimization

- Use spot instances for non-critical workloads
- Configure autoscaling based on actual usage
- Review and optimize resource requests/limits
- Use Azure Reserved Instances for predictable workloads
- Enable diagnostic logs only for production environments
