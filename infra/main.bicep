param workspaceName string
param failedSigninRuleGuid string

module failedSignins '../detections/sentinel/scheduled/multiple-failed-signins.bicep' = {
  name: 'failed-signin-rule'
  params: {
    workspaceName: workspaceName
    ruleGuid: failedSigninRuleGuid
  }
}
