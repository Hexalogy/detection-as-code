param workspaceName string
param failedSigninRuleGuid string
@description('Stable GUID for the Azure RBAC role-assignment detection.')
param azureRbacRoleAssignmentRuleGuid string

module failedSignins '../detections/sentinel/scheduled/multiple-failed-signins.bicep' = {
  name: 'failed-signin-rule'
  params: {
    workspaceName: workspaceName
    ruleGuid: failedSigninRuleGuid
  }
}

module azureRbacRoleAssignment '../detections/sentinel/scheduled/azure-rbac-role-assignment.bicep' = {
  name: 'azure-rbac-role-assignment-rule'
  params: {
    workspaceName: workspaceName
    ruleGuid: azureRbacRoleAssignmentRuleGuid
  }
}
