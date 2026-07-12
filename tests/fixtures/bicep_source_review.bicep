targetScope = 'resourceGroup'

@secure()
param adminPassword string
param location string = resourceGroup().location

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'readtheplanstorage'
  location: location
  properties: {
    publicNetworkAccess: 'Disabled'
    allowBlobPublicAccess: false
  }
}

module diagnostics './diagnostics.bicep' = {
  name: 'diagnostics'
  params: {
    location: location
  }
}
