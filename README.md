
## Connecting Microsoft Entra --> Log Analytics Workspace

### Make Sentinel send logs straight to LAW


<img width="1799" height="665" alt="image" src="https://github.com/user-attachments/assets/d4e84f2a-f1e4-44ac-9098-a181b27e3a50" />

the complete chain looks like this: 
`Entra sign-in` → `SigninLogs ingestion` → `KQL matches` → `Sentinel rule creates an alert`.

# Prove an Alert
## 1. Generate sign-in event

In a private/InPrivate browser window:

1.  Go to [Microsoft 365](https://www.office.com/) or [Azure portal](https://portal.azure.com/).
    
2.  Sign in using your own Entra account normally.
    
3.  Sign out.
    

This creates a successful sign-in event.

Then wait 5–10 minutes and open:

`Microsoft Sentinel → law-dac-dev-001 → Logs`

Run:

```
SigninLogs 
| where TimeGenerated > ago(24h)
| project TimeGenerated, UserPrincipalName, ResultType, ResultDescription, IPAddress, AppDisplayName
| order by TimeGenerated desc
| take 50```
```
It should return a row of when you logged in.

## 2. Generate failed sign-in event

- ive reduce the test threshold in the bicep `detections/sentinel/scheduled/multiple-failed-signins.bicep` file to `2`
- `| where FailedAttempts >= 2`
- `description: 'LAB TEST ONLY: Triggers when an IP address generates two or more failed Entra ID sign-ins.'`

- I've created a test account called "DaC Test User" (dac-test@renegadexwarslive.onmicrosoft.com) so I can purposely sign-in with the wrong password to trigger the alert
<img width="1555" height="634" alt="image" src="https://github.com/user-attachments/assets/b57cc00f-3648-41dc-9721-957730ee3d87" />

UPDATE: after some troubleshooting, looks like i needed to connect Microsoft Sentinel to Microsoft Defender first, in order to do that, id have to add Sentinel Workspace onto Defender.
<img width="1643" height="518" alt="image" src="https://github.com/user-attachments/assets/4477a93a-c609-4c26-848b-cbb040354022" />

voila! now I can see the alert ("DaC - Multiple failed sign-ins from one IP") on Sentinel.
*p.s. the screenshot below is outdated because then Azure will tell you to go to Defender shortly after*
<img width="1469" height="654" alt="image" src="https://github.com/user-attachments/assets/f12afab3-0df0-4807-b6f5-77816624d433" />

1:32 8/24/26:
ive been trying to figure out how to get the **Rules** to show on Defender and it has finally worked. I think the issue was that you see the changes until you sign out and then back in to force to 'refresh'

<img width="2804" height="1232" alt="image" src="https://github.com/user-attachments/assets/c7d80f16-9129-4302-a12b-63afdb70f620" />

8/26/2026:
Finally, got the **Alerts** and Incidents to show up in Microsoft Defender (MS has been nagging users to move away from Sentinel -> Defender)

<img width="1873" height="826" alt="image" src="https://github.com/user-attachments/assets/9315a754-5661-4f0c-ac72-ad8972bde3d2" />
👏👏

The problem was URBAC permission issue


Summary of the Full Fix Chain
-----------------------------

The complete resolution path across this whole troubleshooting session was:

1.  Added the missing `incidentConfiguration` block to the Bicep template so the rule actually creates incidents from alerts.
    
2.  Confirmed the redeployed rule JSON matched intent (no ETag/drift issues).
    
3.  Ruled out the `SigninLogs` table plan (already Analytics).
    
4.  Confirmed detection was working end-to-end by finding rows in `SecurityAlert`/`SecurityIncident` directly.
    
5.  Assigned Azure RBAC roles (Sentinel Contributor/Reader/Responder) on the resource group.
    
6.  Found the true blocker: the **auto-imported URBAC role permission sets** were incomplete, missing "Alerts (manage)," and switching to "All read and manage permissions" fixed visibility.

## Phase 2 - Added `detections/sigma/multiple-failed-signins.yml`

