@description('Existing Log Analytics workspace name.')
param workspaceName string

@description('Deployment region.')
param location string = resourceGroup().location

@description('Stable GUID for this analytics rule. Do not change after initial deployment.')
param ruleGuid string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource rule 'Microsoft.SecurityInsights/alertRules@2024-03-01-preview' = {
  name: '${workspace.name}/${ruleGuid}'
  kind: 'Scheduled'
  properties: {
    displayName: 'DaC - Azure RBAC role assignment created'
    description: 'Detects successful Azure RBAC role-assignment creation events in Azure Activity logs. Investigate unexpected privilege grants, especially assignments to privileged roles or at broad scope.'
    severity: 'High'
    enabled: true
    query: '''
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue =~ "Success"
| extend PropertiesJson = parse_json(Properties)
| extend AssignmentStatus = tostring(PropertiesJson.statusCode)
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, AssignmentStatus, ResourceGroup, ResourceId, SubscriptionId, CorrelationId, Properties
'''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: [
      'Persistence'
      'PrivilegeEscalation'
    ]
    techniques: [
      'T1098'
    ]
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Azure RBAC role assignment created by {{Caller}}'
      alertDescriptionFormat: 'Successful role assignment write by {{Caller}} from {{CallerIpAddress}} in resource group {{ResourceGroup}}.'
      alertDynamicProperties: []
    }
    customDetails: {
      Caller: 'Caller'
      CallerIP: 'CallerIpAddress'
      ResourceGroup: 'ResourceGroup'
      ResourceId: 'ResourceId'
      AssignmentStatus: 'AssignmentStatus'
      CorrelationId: 'CorrelationId'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: false
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
}
