@description('Existing Log Analytics workspace name.')
param workspaceName string

@description('Deployment region.')
param location string = resourceGroup().location

@description('A stable GUID for this analytics rule. Do not change after first deployment.')
param ruleGuid string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource rule 'Microsoft.SecurityInsights/alertRules@2024-03-01-preview' = {
  name: '${workspace.name}/${ruleGuid}'
  kind: 'Scheduled'
  properties: {
    displayName: 'DaC - Multiple failed sign-ins from one IP'
    description: 'Triggers when an IP address generates repeated failed Entra ID sign-ins.'
    severity: 'Medium'
    enabled: true

    query: '''
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize FailedAttempts = count(), Accounts = dcount(UserPrincipalName)
    by IPAddress, bin(TimeGenerated, 15m)
| where FailedAttempts >= 10
'''

    queryFrequency: 'PT15M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
    ]
    techniques: [
      'T1110'
    ]
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Possible password spraying from {{IPAddress}}'
      alertDescriptionFormat: '{{FailedAttempts}} failed sign-ins across {{Accounts}} accounts.'
      alertDynamicProperties: []
    }
    customDetails: {
      SourceIP: 'IPAddress'
      FailedAttempts: 'FailedAttempts'
      AccountsTargeted: 'Accounts'
    }
  }
}