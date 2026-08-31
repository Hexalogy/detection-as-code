

## Connecting Microsoft Entra --> Log Analytics Workspace

### Make Sentinel send logs straight to LAW


<img width="1799" height="665" alt="image" src="https://github.com/user-attachments/assets/d4e84f2a-f1e4-44ac-9098-a181b27e3a50" />

the complete chain looks like this: 
`Entra sign-in` → `SigninLogs ingestion` → `KQL matches` → `Sentinel rule creates an alert`.

## Phase 1 - Prove an Alert working
### 1. Generate sign-in event

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

### 2. Generate failed sign-in event

- ive reduce the test threshold in the bicep `detections/sentinel/scheduled/multiple-failed-signins.bicep` file to `2`
- `| where FailedAttempts >= 2`
- `description: 'LAB TEST ONLY: Triggers when an IP address generates two or more failed Entra ID sign-ins.'`

- I've created a test account called "DaC Test User" (dac-test@renegadexwarslive.onmicrosoft.com) so I can purposely sign-in with the wrong password to trigger the alert
<img width="1555" height="634" alt="image" src="https://github.com/user-attachments/assets/b57cc00f-3648-41dc-9721-957730ee3d87" />

UPDATE: after some troubleshooting, looks like I needed to connect Microsoft Sentinel to Microsoft Defender first, in order to do that, id have to add Sentinel Workspace onto Defender.
<img width="1643" height="518" alt="image" src="https://github.com/user-attachments/assets/4477a93a-c609-4c26-848b-cbb040354022" />

voila! now I can see the alert ("DaC - Multiple failed sign-ins from one IP") on Sentinel.
*p.s. the screenshot below is outdated because then Azure will tell you to go to Defender shortly after*
<img width="1469" height="654" alt="image" src="https://github.com/user-attachments/assets/f12afab3-0df0-4807-b6f5-77816624d433" />

### Troubleshoot Steps to show Alerts on MS Defender

1:32 8/24/26:
ive been trying to figure out how to get the **Rules** to show on Defender and it has finally worked. I think the issue was that you see the changes until you sign out and then back in to force to 'refresh'

<img width="2804" height="1232" alt="image" src="https://github.com/user-attachments/assets/c7d80f16-9129-4302-a12b-63afdb70f620" />

8/26/2026:
Finally, got the **Alerts** and Incidents to show up in Microsoft Defender (MS has been nagging users to move away from Sentinel -> Defender)

<img width="1873" height="826" alt="image" src="https://github.com/user-attachments/assets/9315a754-5661-4f0c-ac72-ad8972bde3d2" />
👏👏

The problem was URBAC permission issue


### 3. Summary of the Full Fix Chain

The complete resolution path across this whole troubleshooting session was:

1.  Added the missing `incidentConfiguration` block to the Bicep template so the rule actually creates incidents from alerts.
    
2.  Confirmed the redeployed rule JSON matched intent (no ETag/drift issues).
    
3.  Ruled out the `SigninLogs` table plan (already Analytics).
    
4.  Confirmed detection was working end-to-end by finding rows in `SecurityAlert`/`SecurityIncident` directly.
    
5.  Assigned Azure RBAC roles (Sentinel Contributor/Reader/Responder) on the resource group.
    
6.  Found the true blocker: the **auto-imported URBAC role permission sets** were incomplete, missing "Alerts (manage)," and switching to "All read and manage permissions" fixed visibility.

## Phase 2 - First Sigma File

`detections/sigma/multiple-failed-signins.yml`
Sigma file is basically a **recipe written in plain English** ("brown the onions, then add garlic") and the Bicep file is **that same recipe translated into French, with exact gram measurements, for a specific French cookbook publisher**.

-   The recipe idea - "detect a successful role assignment" - is the Sigma file.
    
-   The Bicep file is *that* idea rewritten in Azure's specific query language (KQL) that only Azure can understand.

If you ever switched SIEM vendors - say, to Splunk - you would **not** rewrite the Sigma file. You'd feed it to a converter.

So far I have:

- A Sentinel Bicep rule

- A human-readable Sigma file

- A test contract with positive and negative cases

- A validation gate that checks rule/test consistency (`validation.ps1`)

- CI/CD with build, validation, what-if, and deployment


## Phase 3 - Build a Second Detection

### Connect Azure Activity in Azure Monitor

<img width="1220" height="597" alt="image" src="https://github.com/user-attachments/assets/0cea5fe8-c623-4d95-97a1-6e32c5607d0f" />

### Implement Azure-RBAC-role-assigment
- Create a new Bicep rules in detections/sentinel/scheduled

- A new Sigma yaml file in detections/sigma

- New Test file in detections/tests


### Implement Validation.ps1

Refactor the following logic: 

- **Universal checks for every rule**: stable `ruleGuid`, time bound, `description`, `customDetails`, `incidentConfiguration`, tactic mapping, existing Bicep/Sigma/test references, positive and negative tests.

- **Rule-specific checks from each test contract**: expected table, query operation, success/failure condition, threshold, and aggregation.. only where that detection needs them.



### Test Alert

Assign Reader role to the dummy account

Go to Sentinel > Incidents:
<img width="1974" height="1190" alt="image" src="https://github.com/user-attachments/assets/0e1aefdf-2d77-48cd-abc6-a587763ec156" />

