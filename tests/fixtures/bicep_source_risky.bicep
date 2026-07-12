targetScope = 'subscription'

@secure()
param adminPassword string = 'hard-coded-password'

param apiToken string
param location string = 'eastus'

var managementEndpoint = 'https://management.azure.com'
var bootstrapScript = loadTextContent('./bootstrap.sh')

resource existingVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: 'shared-vault'
  scope: resourceGroup('shared-services')
}

resource ownerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, 'owner')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'owner')
    principalId: '00000000-0000-0000-0000-000000000000'
  }
}

resource bootstrap 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'bootstrap'
  location: location
  kind: 'AzureCLI'
  properties: {
    azCliVersion: '2.52.0'
    scriptContent: '''
      set -e
      az account show
    '''
    retentionInterval: 'P1D'
  }
}

resource publicStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'readtheplanpublic'
  location: location
  properties: {
    publicNetworkAccess: 'Enabled'
    allowBlobPublicAccess: true
  }
}

resource completeDeployment 'Microsoft.Resources/deployments@2022-09-01' = {
  name: 'complete-deployment'
  location: location
  properties: {
    mode: 'Complete'
    template: {}
  }
}

module network 'br/public:avm/res/network/virtual-network:0.7.0' = {
  name: 'network'
  scope: subscription()
  params: {
    location: location
  }
}

output storageKey string = listKeys(publicStorage.id, publicStorage.apiVersion).keys[0].value
