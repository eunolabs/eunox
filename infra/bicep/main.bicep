// ----------------------------------------------------------------------------
// Euno Capability-Native Agent Governance — Azure Bicep deployment
// ----------------------------------------------------------------------------
//
// Provisions every Azure resource called out in the Sprint 5 production-pilot
// plan:
//
//   * Resource group scope (use --scope subscription if deploying RG too)
//   * Log Analytics Workspace + Application Insights (workspace-based)
//   * Azure Key Vault (RBAC-mode) + RSA signing key for capability tokens
//   * Azure Container Registry
//   * AKS cluster (system-assigned identity, OIDC issuer, workload identity,
//     Azure Monitor / Container Insights add-on)
//   * User-assigned managed identity for the Capability Issuer + role
//     assignments on the Key Vault and ACR
//   * Diagnostic Settings sending AKS control-plane logs into Log Analytics
//     so Microsoft Sentinel / Sentinel analytic rules can evaluate them
//
// Deploy with:
//
//   az deployment group create \
//     --resource-group euno-rg \
//     --template-file infra/bicep/main.bicep \
//     --parameters @infra/bicep/main.parameters.example.json
//
// All naming is parameterized so the same template can be deployed multiple
// times for staging / pilot / prod.
// ----------------------------------------------------------------------------

@description('Short prefix used to name all resources (3-12 lowercase letters / digits).')
@minLength(3)
@maxLength(12)
param namePrefix string = 'euno'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Tags applied to all resources.')
param tags object = {
  product: 'euno'
  component: 'capability-governance'
  environment: 'pilot'
}

@description('Object ID of the Azure AD user / group that should receive Key Vault Crypto Officer rights for key rotation. Leave empty to skip.')
param keyVaultAdminObjectId string = ''

@description('Kubernetes version for the AKS cluster.')
param kubernetesVersion string = '1.30.6'

@description('Number of system nodes in the AKS default pool.')
@minValue(2)
@maxValue(10)
param aksNodeCount int = 3

@description('VM size for AKS nodes.')
param aksNodeVmSize string = 'Standard_D2s_v5'

@description('Retention period in days for Log Analytics workspace.')
@minValue(30)
@maxValue(730)
param logAnalyticsRetentionDays int = 90

// ---------------------------------------------------------------------------
// Naming
// ---------------------------------------------------------------------------
var suffix = uniqueString(resourceGroup().id, namePrefix)
var lawName = toLower('${namePrefix}-law-${suffix}')
var appInsightsName = toLower('${namePrefix}-ai-${suffix}')
var keyVaultName = toLower('${namePrefix}kv${suffix}')
var acrName = toLower('${namePrefix}acr${suffix}')
var aksName = toLower('${namePrefix}-aks-${suffix}')
var issuerIdentityName = toLower('${namePrefix}-issuer-mi-${suffix}')

// Built-in role definition IDs
var roleKeyVaultCryptoUser = '12338af0-0e69-4776-bea7-57ae8d297424'
var roleKeyVaultCryptoOfficer = '14b46e9e-c2b7-41b4-b07b-48a6ebf60603'
var roleAcrPull = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

// ---------------------------------------------------------------------------
// Log Analytics + Application Insights
// ---------------------------------------------------------------------------
resource law 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: lawName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: logAnalyticsRetentionDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    Flow_Type: 'Bluefield'
    Request_Source: 'rest'
    WorkspaceResourceId: law.id
  }
}

// ---------------------------------------------------------------------------
// Container Registry
// ---------------------------------------------------------------------------
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'Enabled'
  }
}

// ---------------------------------------------------------------------------
// Key Vault + capability signing key
// ---------------------------------------------------------------------------
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enablePurgeProtection: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource signingKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: keyVault
  name: 'capability-signing-key'
  properties: {
    kty: 'RSA'
    keySize: 2048
    keyOps: [
      'sign'
      'verify'
    ]
    attributes: {
      enabled: true
      exportable: false
    }
  }
}

resource keyVaultDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: keyVault
  name: 'send-to-law'
  properties: {
    workspaceId: law.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// User-assigned managed identity for the Capability Issuer workload
// ---------------------------------------------------------------------------
resource issuerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: issuerIdentityName
  location: location
  tags: tags
}

resource issuerKvCryptoUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: keyVault
  name: guid(keyVault.id, issuerIdentity.id, roleKeyVaultCryptoUser)
  properties: {
    principalId: issuerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleKeyVaultCryptoUser)
  }
}

resource adminKvCryptoOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(keyVaultAdminObjectId)) {
  scope: keyVault
  name: guid(keyVault.id, keyVaultAdminObjectId, roleKeyVaultCryptoOfficer)
  properties: {
    principalId: keyVaultAdminObjectId
    principalType: 'User'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleKeyVaultCryptoOfficer)
  }
}

// ---------------------------------------------------------------------------
// AKS cluster
// ---------------------------------------------------------------------------
resource aks 'Microsoft.ContainerService/managedClusters@2024-05-01' = {
  name: aksName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  sku: {
    name: 'Base'
    tier: 'Standard'
  }
  properties: {
    kubernetesVersion: kubernetesVersion
    dnsPrefix: '${namePrefix}${suffix}'
    enableRBAC: true
    oidcIssuerProfile: {
      enabled: true
    }
    securityProfile: {
      workloadIdentity: {
        enabled: true
      }
    }
    agentPoolProfiles: [
      {
        name: 'system'
        mode: 'System'
        count: aksNodeCount
        vmSize: aksNodeVmSize
        osType: 'Linux'
        osDiskType: 'Managed'
        osDiskSizeGB: 64
        type: 'VirtualMachineScaleSets'
        enableAutoScaling: true
        minCount: aksNodeCount
        maxCount: aksNodeCount * 3
        upgradeSettings: {
          maxSurge: '33%'
        }
      }
    ]
    networkProfile: {
      networkPlugin: 'azure'
      networkPolicy: 'azure'
    }
    addonProfiles: {
      omsagent: {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceID: law.id
        }
      }
      azurepolicy: {
        enabled: true
      }
    }
    apiServerAccessProfile: {
      enablePrivateCluster: false
    }
  }
}

resource aksAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: acr
  name: guid(acr.id, aks.id, roleAcrPull)
  properties: {
    principalId: aks.properties.identityProfile.kubeletidentity.objectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleAcrPull)
  }
}

resource aksDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: aks
  name: 'send-to-law'
  properties: {
    workspaceId: law.id
    logs: [
      { categoryGroup: 'audit', enabled: true }
      { categoryGroup: 'allLogs', enabled: true }
    ]
    metrics: [
      { category: 'AllMetrics', enabled: true }
    ]
  }
}

// ---------------------------------------------------------------------------
// Outputs — feed these into the Helm/kubectl deploy and into the GitHub
// Action / Bicep parameters for downstream environments.
// ---------------------------------------------------------------------------
output logAnalyticsWorkspaceId string = law.id
output appInsightsConnectionString string = appInsights.properties.ConnectionString
output appInsightsInstrumentationKey string = appInsights.properties.InstrumentationKey
output keyVaultUri string = keyVault.properties.vaultUri
output keyVaultName string = keyVault.name
output signingKeyName string = signingKey.name
output signingKeyVersionUrl string = signingKey.properties.keyUriWithVersion
output acrLoginServer string = acr.properties.loginServer
output aksName string = aks.name
output aksOidcIssuerUrl string = aks.properties.oidcIssuerProfile.issuerURL
output issuerIdentityClientId string = issuerIdentity.properties.clientId
output issuerIdentityResourceId string = issuerIdentity.id
