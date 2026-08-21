param workspaceName string
param location string = resourceGroup().location
param failedSigninRuleGuid string

module failedSignins '../detections/sentinel/scheduled/multiple-failed-signins.bicep' = {
  name: 'failed-signin-rule'
  params: {
    workspaceName: workspaceName
    location: location
    ruleGuid: failedSigninRuleGuid
  }
}
