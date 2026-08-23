## Connecting Microsoft Entra --> Log Analytics Workspace

### Make Sentinel send logs straight to LAW


<img width="1799" height="665" alt="image" src="https://github.com/user-attachments/assets/d4e84f2a-f1e4-44ac-9098-a181b27e3a50" />

the complete chain looks like this: 
Entra sign-in → SigninLogs ingestion → KQL matches → Sentinel rule creates an alert.

1\. Generate one safe sign-in event
-----------------------------------

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
