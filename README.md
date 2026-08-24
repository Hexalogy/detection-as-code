## Connecting Microsoft Entra --> Log Analytics Workspace

### Make Sentinel send logs straight to LAW


<img width="1799" height="665" alt="image" src="https://github.com/user-attachments/assets/d4e84f2a-f1e4-44ac-9098-a181b27e3a50" />

the complete chain looks like this: 
Entra sign-in → SigninLogs ingestion → KQL matches → Sentinel rule creates an alert.

# Prove an Alert
## 1. Generate sign-in event

In a private/InPrivate browser window:

1.  Go to [Microsoft 365](https://www.office.com/) or [Azure portal](https://portal.azure.com/).
    
2.  Sign in using your own Entra account normally.
    
3.  Complete MFA if prompted.
    
4.  Sign out.
    

This creates a successful sign-in event.

Then wait 5–10 minutes and open:

`Microsoft Sentinel → law-dac-dev-001 → Logs   `

Run:

```
SigninLogs 
| where TimeGenerated > ago(24h)
| project TimeGenerated, UserPrincipalName, ResultType, ResultDescription, IPAddress, AppDisplayName
| order by TimeGenerated desc
| take 50```
```
and you should be able to see the time when you log in

## 2. Generate failed sign-in event

- ive modified the bicep detections/sentinel/scheduled/multiple-failed-signins.bicep file to
- `| where FailedAttempts >= 2`
- `description: 'LAB TEST ONLY: Triggers when an IP address generates two or more failed Entra ID sign-ins.'`

- now ive created another account called "DaC Test User" (dac-test@renegadexwarslive.onmicrosoft.com) so I can purposely  sign-in with the wrong password to trigger the alert
<img width="1555" height="634" alt="image" src="https://github.com/user-attachments/assets/b57cc00f-3648-41dc-9721-957730ee3d87" />

UPDATE: after some troubleshooting, looks like i needed to connect Microsoft Sentinel to Microsoft Defender first, in order to do that, id have to add Sentintel Workspace onto Defender.
<img width="1643" height="518" alt="image" src="https://github.com/user-attachments/assets/4477a93a-c609-4c26-848b-cbb040354022" />

voila! now I can see the alert ("DaC - Multiple failed sign-ins from one IP") on Sentinel
<img width="1469" height="654" alt="image" src="https://github.com/user-attachments/assets/f12afab3-0df0-4807-b6f5-77816624d433" />

1:32 8/24/26:
ive been trying to figure out how to get it to show on Defender and it has finally worked. I think the issue was that you see the changes until you sign out and then back in to force to 'refresh'

<img width="2804" height="1232" alt="image" src="https://github.com/user-attachments/assets/c7d80f16-9129-4302-a12b-63afdb70f620" />




