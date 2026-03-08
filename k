
1. BANK-ID-CHAIN-001 - Risky Sign-in Followed by Privileged Identity Action
2. BANK-OAUTH-GRAPH-002 - OAuth Consent or App Secret Addition Followed by Graph Enumeration
3. BANK-MI-AZCTRL-003 - Managed Identity Sign-in Followed by Sensitive Azure Control Plane Change
4. BANK-BEC-CHAIN-004 - Delivered Phish → Click → Cloud Sign-in → Mailbox Forwarding or Inbox Rule
5. BANK-MAIL-MALWARE-005 - Malicious Email Delivered Followed by Endpoint Execution and Cloud Persistence
6. BANK-ENDPOINT-CROWN-006 - Suspicious Execution on Crown-Jewel Server Followed by Risky Cloud Identity Activity
7. BANK-AZ-CTRL-007 - Suspicious Sign-in Followed by Azure Security Control Degradation
8. BANK-SPN-DORMANT-008 - Dormant or First-Seen Service Principal Reactivated for Sensitive API Use
9. BANK-SAAS-ADMIN-009 - Uncommon SaaS Admin Operation With Risky Identity Context
10. BANK-CAMPAIGN-010 - Malicious Mail Campaign With at Least One Real Compromise
11. BANK-META-IDENTITY-011 - Composite Identity Compromise Score
12. BANK-ENDPOINT-PERSIST-012 - Endpoint Persistence Added on Server/VM With External Network Activity
13. ENTRA-PRIV-CHAIN-01 - Risky sign-in → privileged role assignment
14. ENTRA-PRIV-CHAIN-02 - Risky sign-in → MFA / authentication method tampering
15. ENTRA-OAUTH-CHAIN-03 - OAuth consent / secret add → service principal sign-in → Graph sensitive enumeration
16. ENTRA-SPN-04 - Dormant/new service principal reactivated for sensitive APIs
17. ENTRA-MI-05 - Managed identity sign-in anomaly → Azure control-plane write
18. AZ-CTRL-06 - Risky user sign-in → role assignment / policy exemption / diagnostic deletion
19. AZ-EXPOSURE-07 - Suspicious sign-in → NSG opens SSH/RDP/WinRM to Internet
20. M365-BEC-08 - Delivered phish → click → cloud sign-in → mailbox forwarding
21. M365-CAMPAIGN-09 - Phishing campaign → multiple recipients → click(s) → at least one real compromise
22. M365-OAUTH-MAIL-10 - Mailbox forwarding + OAuth consent by same user
23. M365-DATA-11 - Suspicious sign-in → SharePoint/OneDrive mass download
24. M365-TRAVEL-12 - Country switch + mail/file actions in short window
25. XDR-CLOUD-PIVOT-13 - Office/browser child process → external network → cloud persistence
26. SERVER-CROWN-14 - Critical server suspicious process + risky user context
27. SERVER-LOLBIN-15 - Encoded PowerShell / LOLBIN → public network from server or VM
28. XDR-DEFENSE-EVASION-16 - Security control disabled → suspicious execution soon after
29. XDR-RANSOM-PRE-17 - Ransomware precursor: shadow copy disable / backup sabotage → mass file modifications
30. SAAS-ADMIN-18 - Uncommon SaaS admin operation + risky identity context
31. META-IDENTITY-19 - Composite identity compromise score
32. META-ENTITY-20 - User + device + app + alert evidence fusion
33. Table glossary and correlation notes

================================================================================
1) BANK-ID-CHAIN-001
Rule name:
BANK-ID-CHAIN-001 - Risky Sign-in Followed by Privileged Identity Action

KQL:
let RiskySignin = materialize(
    SigninLogs
    | where TimeGenerated >= ago(2h)
    | where ResultType == 0
    | where IsRisky == true or RiskLevelDuringSignIn in~ ("high","medium")
    | project SigninTime=TimeGenerated, UPN=UserPrincipalName, SigninIP=IPAddress, AppDisplayName, ConditionalAccessStatus, RiskLevelDuringSignIn, RiskDetail
);
let SensitiveAudit = materialize(
    AuditLogs
    | where ActivityDateTime >= ago(2h)
    | where ActivityDisplayName has_any (
        "Add member to role",
        "Add eligible member to role",
        "Add member to directory role",
        "Grant consent to application",
        "Consent to application",
        "Add service principal credentials",
        "Update application - Certificates and secrets management",
        "Register security info",
        "Delete security info",
        "Update authentication method",
        "Reset password (by admin)"
    )
    | extend InitiatorUPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
    | extend InitiatorApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
    | extend Actor = coalesce(InitiatorUPN, InitiatorApp)
    | project AuditTime=ActivityDateTime, Actor, ActivityDisplayName, Result, ResultReason, CorrelationId, TargetResources
);
let IdCtx =
    IdentityInfo
    | summarize arg_max(Timestamp, *) by AccountUpn
    | project AccountUpn, CriticalityLevel, BlastRadius, AccountObjectId, AssignedRoles=Tags;
let PriorAlerts =
    SecurityAlert
    | where TimeGenerated >= ago(24h)
    | summarize PriorAlertCount=count(), AlertNames=make_set(AlertName, 10) by CompromisedEntity;
RiskySignin
| join kind=inner SensitiveAudit on $left.UPN == $right.Actor
| where AuditTime between (SigninTime .. SigninTime + 60m)
| join kind=leftouter IdCtx on $left.UPN == $right.AccountUpn
| join kind=leftouter PriorAlerts on $left.UPN == $right.CompromisedEntity
| extend Score =
    35
    + iff(RiskLevelDuringSignIn =~ "high", 20, 10)
    + iff(PriorAlertCount > 0, 10, 0)
    + iff(ActivityDisplayName has_any ("Add member to role","Grant consent to application","Add service principal credentials"), 20, 10)
| where Score >= 55
| project SigninTime, AuditTime, UPN, SigninIP, AppDisplayName, ConditionalAccessStatus, RiskLevelDuringSignIn, RiskDetail,
          ActivityDisplayName, Result, ResultReason, CorrelationId, BlastRadius, CriticalityLevel, PriorAlertCount, AlertNames, Score

Explanation:
Detects a risky or high-risk Entra sign-in followed by a privileged or persistence-related identity action.
This is a high-value account takeover or privileged misuse correlation.

Tables connection:
- SigninLogs provides the initial risky login
- AuditLogs provides the privileged action or persistence step
- IdentityInfo adds account criticality and blast radius context
- SecurityAlert adds prior alert history for confidence boosting

Impact:
High. This can indicate post-authentication privilege escalation, persistence establishment,
or administrative abuse after user compromise.

Why needed:
Single risky sign-ins are noisy. Single audit events are also often operationally ambiguous.
The combination of both in a short sequence has much stronger investigative value.

Rule config:
- Recommended engine: Sentinel Scheduled
- Frequency: 5 minutes
- Lookback: 2 hours
- Severity: High
- Grouping key: UPN
- Suggested MITRE: Initial Access, Privilege Escalation, Persistence

Expected noise:
Medium if the environment has many admins performing regular changes.
Lower if scoped to privileged users or high-value accounts.

How to tune:
- Exclude break-glass or approved admin identities
- Exclude known admin IP ranges
- Restrict to sensitive ActivityDisplayName values only
- Increase threshold if risk level is medium and false positives are too high

================================================================================
2) BANK-OAUTH-GRAPH-002
Rule name:
BANK-OAUTH-GRAPH-002 - OAuth Consent or App Secret Addition Followed by Graph Enumeration

KQL:
let AppEstablish =
    AuditLogs
    | where ActivityDateTime >= ago(6h)
    | where ActivityDisplayName has_any (
        "Grant consent to application",
        "Consent to application",
        "Add service principal credentials",
        "Update application - Certificates and secrets management"
    )
    | extend InitiatorUPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
    | extend TargetApp = tostring(TargetResources[0].displayName)
    | project EstablishTime=ActivityDateTime, InitiatorUPN, TargetApp, ActivityDisplayName, CorrelationId, Props=tostring(TargetResources);
let SpnSignin =
    AADServicePrincipalSignInLogs
    | where TimeGenerated >= ago(6h)
    | where ResultType == 0
    | summarize FirstSPSignin=min(TimeGenerated), SPIPs=make_set(IPAddress,10), SPNames=make_set(ServicePrincipalName,5)
      by AppId, ServicePrincipalId;
let GraphBurst =
    MicrosoftGraphActivityLogs
    | where TimeGenerated >= ago(6h)
    | where ResponseStatusCode between (200 .. 299)
    | where RequestUri has_any ("/users", "/groups", "/directoryRoles", "/roleManagement", "/auditLogs", "/messages", "/mailFolders", "/sites", "/drives", "/applications", "/servicePrincipals")
    | summarize GraphCalls=count(), DistinctUris=dcount(RequestUri), FirstGraph=min(TimeGenerated), LastGraph=max(TimeGenerated), URIs=make_set(RequestUri, 20)
      by AppId, ServicePrincipalId
    | where GraphCalls >= 40 and DistinctUris >= 5;
let PriorAlerts =
    SecurityAlert
    | where TimeGenerated >= ago(7d)
    | summarize PriorAlertCount=count(), AlertNames=make_set(AlertName, 10) by CompromisedEntity;
GraphBurst
| join kind=inner SpnSignin on AppId, ServicePrincipalId
| join kind=inner AppEstablish on $left.SPNames has $right.TargetApp
| where FirstSPSignin between (EstablishTime .. EstablishTime + 2h) or FirstGraph between (EstablishTime .. EstablishTime + 2h)
| join kind=leftouter PriorAlerts on $left.TargetApp == $right.CompromisedEntity
| extend Score =
    40
    + iff(ActivityDisplayName has_any ("Add service principal credentials","Update application - Certificates and secrets management"), 20, 10)
    + iff(GraphCalls > 100, 20, 10)
    + iff(PriorAlertCount > 0, 10, 0)
| where Score >= 60
| project EstablishTime, FirstSPSignin, FirstGraph, LastGraph, InitiatorUPN, TargetApp, ActivityDisplayName, Props,
          AppId, ServicePrincipalId, SPIPs, GraphCalls, DistinctUris, URIs, PriorAlertCount, AlertNames, CorrelationId, Score

Explanation:
Detects suspicious application establishment activity followed by real operational use
through Microsoft Graph, which is a strong indicator of malicious app persistence or app secret theft.

Tables connection:
- AuditLogs records consent or secret/certificate additions
- AADServicePrincipalSignInLogs confirms the app signed in
- MicrosoftGraphActivityLogs confirms the app was actively used against sensitive APIs
- SecurityAlert adds prior alert context

Impact:
Very high. This can represent long-lived stealthy access to mail, files, directory objects, or roles.

Why needed:
OAuth and app identity abuse is one of the most dangerous cloud attack paths because it can outlive user session remediation.

Rule config:
- Recommended engine: Sentinel Scheduled
- Frequency: 10 minutes
- Lookback: 6 hours
- Severity: High
- Suggested MITRE: Persistence, Privilege Escalation, Collection, Exfiltration

Expected noise:
Low to medium if many legitimate app onboarding or DevOps changes exist.
Usually lower than user-based rules when focused on sensitive Graph endpoints.

How to tune:
- Maintain ApprovedOAuthApps watchlist
- Parse AppId directly from audit payloads where possible instead of display name matching
- Exclude known automation and provisioning apps
- Raise GraphCalls threshold for very large tenants

================================================================================
3) BANK-MI-AZCTRL-003
Rule name:
BANK-MI-AZCTRL-003 - Managed Identity Sign-in Followed by Sensitive Azure Control Plane Change

KQL:
let MI_Signins =
    AADManagedIdentitySignInLogs
    | where TimeGenerated >= ago(3h)
    | where ResultType == 0
    | project MISigninTime=TimeGenerated, Identity=tostring(Identity), ManagedIdentityResourceId=tostring(ResourceId), AppId, SigninIP=IPAddress, ServicePrincipalId;
let DangerousControlPlane =
    AzureActivity
    | where TimeGenerated >= ago(3h)
    | where ActivityStatusValue =~ "Succeeded"
    | where OperationNameValue has_any (
        "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
        "MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE",
        "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
        "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
        "MICROSOFT.AUTHORIZATION/POLICYEXEMPTIONS/WRITE",
        "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
        "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION"
    )
    | project ActivityTime=TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceId, SubscriptionId, Properties;
MI_Signins
| join kind=inner DangerousControlPlane on $left.Identity == $right.Caller
| where ActivityTime between (MISigninTime .. MISigninTime + 90m)
| extend Score =
    40
    + iff(OperationNameValue has_any ("ROLEASSIGNMENTS/WRITE","LISTKEYS/ACTION","DIAGNOSTICSETTINGS/DELETE"), 25, 10)
| where Score >= 60
| project MISigninTime, ActivityTime, Identity, ManagedIdentityResourceId, AppId, SigninIP, CallerIpAddress, OperationNameValue, ResourceId, SubscriptionId, Properties, Score

Explanation:
Detects workload identity abuse by correlating managed identity authentication with high-risk Azure control-plane activity.

Tables connection:
- AADManagedIdentitySignInLogs shows the workload identity authenticated
- AzureActivity shows what it changed in Azure control plane

Impact:
Very high in cloud-native finance environments. A compromised workload identity can modify RBAC,
policies, key vault access, or storage access behavior.

Why needed:
Managed identities are often overlooked but can be more privileged than humans.

Rule config:
- Recommended engine: Sentinel Scheduled
- Frequency: 5 minutes
- Lookback: 3 hours
- Severity: High
- Suggested MITRE: Privilege Escalation, Defense Evasion, Credential Access

Expected noise:
Low in most environments because managed identities should have predictable behavior.

How to tune:
- Baseline expected managed identity activities by resource
- Exclude deployment pipelines with approved behavior
- Split by subscription sensitivity if needed

================================================================================
4) BANK-BEC-CHAIN-004
Rule name:
BANK-BEC-CHAIN-004 - Delivered Phish → Click → Cloud Sign-in → Mailbox Forwarding or Inbox Rule

KQL:
let DeliveredPhish =
    EmailEvents
    | where Timestamp >= ago(24h)
    | where DeliveryAction !in~ ("Blocked","Dropped","Rejected")
    | where ThreatTypes has_any ("Phish","Malware")
    | project MsgTime=Timestamp, Recipient=RecipientEmailAddress, NetworkMessageId, Sender=SenderFromAddress, Subject, ThreatTypes;
let Clicks =
    UrlClickEvents
    | where Timestamp >= ago(24h)
    | summarize FirstClick=min(Timestamp), ClickUrls=make_set(Url, 10) by NetworkMessageId, AccountUpn;
let Signins =
    SigninLogs
    | where TimeGenerated >= ago(24h)
    | where ResultType == 0
    | project SigninTime=TimeGenerated, UPN=UserPrincipalName, IPAddress, AppDisplayName, IsRisky, RiskLevelDuringSignIn, ConditionalAccessStatus;
let MailTamper =
    OfficeActivity
    | where TimeGenerated >= ago(24h)
    | where OfficeWorkload == "Exchange"
    | where Operation in~ ("New-InboxRule","Set-InboxRule","Set-Mailbox","Add-MailboxPermission","UpdateInboxRules")
    | where Parameters has_any ("ForwardingSmtpAddress","RedirectTo","ForwardTo","DeliverToMailboxAndForward")
    | project TamperTime=TimeGenerated, UserId, ClientIP, Operation, Parameters;
let IdCtx =
    IdentityInfo
    | summarize arg_max(Timestamp, *) by AccountUpn
    | project AccountUpn, BlastRadius, CriticalityLevel;
DeliveredPhish
| join kind=inner Clicks on NetworkMessageId
| join kind=inner Signins on $left.Recipient == $right.UPN
| where SigninTime between (FirstClick .. FirstClick + 6h)
| join kind=inner MailTamper on $left.Recipient == $right.UserId
| where TamperTime between (SigninTime .. SigninTime + 6h)
| join kind=leftouter IdCtx on $left.Recipient == $right.AccountUpn
| extend Score =
    45
    + iff(IsRisky == true or RiskLevelDuringSignIn in~ ("high","medium"), 20, 10)
    + iff(Operation in~ ("Set-Mailbox","Add-MailboxPermission"), 20, 10)
    + iff(BlastRadius =~ "High", 10, 0)
| where Score >= 65
| project MsgTime, FirstClick, SigninTime, TamperTime, Recipient, Sender, Subject, ThreatTypes, ClickUrls,
          IPAddress, AppDisplayName, ConditionalAccessStatus, IsRisky, RiskLevelDuringSignIn, Operation, Parameters, ClientIP, BlastRadius, CriticalityLevel, Score

Explanation:
This is a full business email compromise chain: phishing email delivery, user click, cloud authentication,
and mailbox persistence.

Tables connection:
- EmailEvents shows delivery of the phishing or malware email
- UrlClickEvents confirms human interaction
- SigninLogs confirms a cloud sign-in happened after the click
- OfficeActivity confirms mailbox persistence
- IdentityInfo adds account criticality

Impact:
Critical in finance environments. This can lead to invoice fraud, payment diversion, or executive email compromise.

Why needed:
This correlation dramatically reduces mail noise and promotes only high-confidence compromise paths.

Rule config:
- Recommended engine: Defender Custom Detection or Sentinel if AH data is streamed
- Frequency: 15 minutes
- Lookback: 24 hours
- Severity: High
- Suggested MITRE: Initial Access, Persistence, Collection

Expected noise:
Low if all four stages are required. Medium if phishing classification is noisy in the tenant.

How to tune:
- Exclude approved forwarding users or service mailboxes
- Restrict to external forwarding only
- Raise time tightness if needed
- Apply higher priority to finance, treasury, executive, and AP/AR users

================================================================================
5) BANK-MAIL-MALWARE-005
Rule name:
BANK-MAIL-MALWARE-005 - Malicious Email Delivered Followed by Endpoint Execution and Cloud Persistence

KQL:
let MalMail =
    EmailEvents
    | where Timestamp >= ago(24h)
    | where DeliveryAction !in~ ("Blocked","Dropped","Rejected")
    | where ThreatTypes has_any ("Malware","Phish")
    | project Recipient=RecipientEmailAddress, MsgTime=Timestamp, Sender=SenderFromAddress, Subject, NetworkMessageId;
let SuspiciousProc =
    DeviceProcessEvents
    | where Timestamp >= ago(24h)
    | where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe")
       or ProcessCommandLine has_any ("-enc","-encodedcommand","FromBase64String","DownloadString(","IEX(","http://","https://")
    | project ProcTime=Timestamp, DeviceName, DeviceId, AccountUpn=InitiatingProcessAccountUpn, FileName, ProcessCommandLine, InitiatingProcessFileName;
let SuspiciousNet =
    DeviceNetworkEvents
    | where Timestamp >= ago(24h)
    | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe")
    | where RemoteIPType == "Public" or isnotempty(RemoteUrl)
    | project NetTime=Timestamp, DeviceId, RemoteIP, RemoteUrl, InitiatingProcessFileName;
let CloudPersist =
    union isfuzzy=true
    (
        AuditLogs
        | where ActivityDateTime >= ago(24h)
        | where ActivityDisplayName has_any ("Grant consent to application","Add service principal credentials","Register security info","Delete security info","Update authentication method")
        | extend Actor=tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
        | project CloudTime=ActivityDateTime, Actor, ChangeType=ActivityDisplayName
    ),
    (
        OfficeActivity
        | where TimeGenerated >= ago(24h)
        | where OfficeWorkload == "Exchange"
        | where Operation in~ ("New-InboxRule","Set-InboxRule","Set-Mailbox")
        | where Parameters has_any ("ForwardingSmtpAddress","RedirectTo","ForwardTo")
        | project CloudTime=TimeGenerated, Actor=UserId, ChangeType=Operation
    );
MalMail
| join kind=inner SuspiciousProc on $left.Recipient == $right.AccountUpn
| where ProcTime between (MsgTime .. MsgTime + 12h)
| join kind=inner SuspiciousNet on DeviceId
| where NetTime between (ProcTime .. ProcTime + 30m)
| join kind=inner CloudPersist on $left.Recipient == $right.Actor
| where CloudTime between (NetTime .. NetTime + 6h)
| extend Score = 70
| project MsgTime, ProcTime, NetTime, CloudTime, Recipient, Sender, Subject, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, RemoteIP, RemoteUrl, ChangeType, Score

Explanation:
Detects a malicious email chain that resulted in suspicious endpoint execution, external network communication,
and subsequent cloud persistence.

Tables connection:
- EmailEvents shows malicious email delivery
- DeviceProcessEvents shows likely execution
- DeviceNetworkEvents confirms external communication
- AuditLogs or OfficeActivity shows follow-on cloud persistence

Impact:
Very high. This links phishing, host compromise, and cloud persistence into one incident-grade chain.

Why needed:
It closes the gap between email security, endpoint security, and cloud identity monitoring.

Rule config:
- Recommended engine: Defender Custom Detection
- Frequency: 15 minutes
- Lookback: 24 hours
- Severity: High
- Suggested MITRE: Initial Access, Execution, Command and Control, Persistence

Expected noise:
Low to medium depending on how broad the suspicious process criteria are.

How to tune:
- Tighten suspicious process list
- Exclude known administrative scripting hosts
- Limit to finance users or critical mailboxes for highest priority
- Raise confidence by adding device criticality or prior alert evidence

================================================================================
6) BANK-ENDPOINT-CROWN-006
Rule name:
BANK-ENDPOINT-CROWN-006 - Suspicious Execution on Crown-Jewel Server Followed by Risky Cloud Identity Activity

KQL:
let CriticalServers = _GetWatchlist('CriticalServers') | project DeviceName=tostring(SearchKey);
let CrownProc =
    DeviceProcessEvents
    | where Timestamp >= ago(12h)
    | join kind=inner CriticalServers on DeviceName
    | where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe","regsvr32.exe","schtasks.exe","wmic.exe","psexec.exe")
       or ProcessCommandLine has_any ("-enc","-encodedcommand","DownloadString(","IEX(","Invoke-WebRequest","curl ","wget ")
    | project ProcTime=Timestamp, DeviceName, DeviceId, AccountUpn=InitiatingProcessAccountUpn, FileName, ProcessCommandLine;
let CrownNet =
    DeviceNetworkEvents
    | where Timestamp >= ago(12h)
    | where RemoteIPType == "Public" or isnotempty(RemoteUrl)
    | project NetTime=Timestamp, DeviceId, RemoteIP, RemoteUrl, InitiatingProcessFileName;
let RiskyCloud =
    SigninLogs
    | where TimeGenerated >= ago(12h)
    | where ResultType == 0
    | where IsRisky == true or RiskLevelDuringSignIn in~ ("high","medium")
    | project SigninTime=TimeGenerated, UPN=UserPrincipalName, SigninIP=IPAddress, AppDisplayName, RiskLevelDuringSignIn;
CrownProc
| join kind=inner CrownNet on DeviceId
| where NetTime between (ProcTime .. ProcTime + 30m)
| join kind=inner RiskyCloud on $left.AccountUpn == $right.UPN
| where SigninTime between (ProcTime - 2h .. ProcTime + 6h)
| extend Score = 80
| project ProcTime, NetTime, SigninTime, DeviceName, AccountUpn, FileName, ProcessCommandLine, RemoteIP, RemoteUrl, SigninIP, AppDisplayName, RiskLevelDuringSignIn, Score

Explanation:
Correlates suspicious execution on a crown-jewel server or VM with risky cloud identity activity by the same user.

Tables connection:
- CriticalServers watchlist identifies crown-jewel assets
- DeviceProcessEvents shows suspicious execution
- DeviceNetworkEvents confirms public egress
- SigninLogs adds risky cloud identity context

Impact:
Critical. This can indicate a compromised privileged user touching a highly sensitive server.

Why needed:
Not all hosts are equal. The same behavior on a normal workstation is very different on a payment bridge or privileged jump server.

Rule config:
- Recommended engine: Defender Custom Detection
- Frequency: 10 minutes
- Lookback: 12 hours
- Severity: Critical on Tier 0 / payment servers
- Suggested MITRE: Execution, Lateral Movement, Credential Access

Expected noise:
Low on truly critical assets, higher if the CriticalServers watchlist is too broad.

How to tune:
- Keep the crown-jewel asset list precise
- Separate admin maintenance windows
- Exclude known management tooling where appropriate
- Add device role tags or server classes

================================================================================
7) BANK-AZ-CTRL-007
Rule name:
BANK-AZ-CTRL-007 - Suspicious Sign-in Followed by Azure Security Control Degradation

KQL:
let SuspiciousSignin =
    SigninLogs
    | where TimeGenerated >= ago(3h)
    | where ResultType == 0
    | where IsRisky == true or RiskLevelDuringSignIn in~ ("high","medium")
    | project SigninTime=TimeGenerated, UPN=UserPrincipalName, SigninIP=IPAddress, RiskLevelDuringSignIn;
let ControlTamper =
    AzureActivity
    | where TimeGenerated >= ago(3h)
    | where ActivityStatusValue =~ "Succeeded"
    | where OperationNameValue has_any (
        "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
        "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
        "MICROSOFT.AUTHORIZATION/POLICYEXEMPTIONS/WRITE",
        "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
        "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
        "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/DELETE",
        "MICROSOFT.SECURITYINSIGHTS/AUTOMATIONRULES/DELETE"
    )
    | project ActivityTime=TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceId, SubscriptionId, Properties;
SuspiciousSignin
| join kind=inner ControlTamper on $left.UPN == $right.Caller
| where ActivityTime between (SigninTime .. SigninTime + 90m)
| extend Score =
    45
    + iff(OperationNameValue has_any ("DIAGNOSTICSETTINGS/DELETE","ALERTRULES/DELETE","ROLEASSIGNMENTS/WRITE"), 25, 10)
| where Score >= 60
| project SigninTime, ActivityTime, UPN, SigninIP, CallerIpAddress, RiskLevelDuringSignIn, OperationNameValue, ResourceId, SubscriptionId, Properties, Score

Explanation:
Detects cloud identity compromise or misuse that leads to weakening of security controls or role changes in Azure.

Tables connection:
- SigninLogs identifies suspicious user authentication
- AzureActivity confirms sensitive control-plane changes

Impact:
High to critical. Attackers often weaken telemetry and controls before deeper persistence or exfiltration.

Why needed:
Security control degradation is a strong attacker objective and should rarely happen after a risky sign-in.

Rule config:
- Recommended engine: Sentinel Scheduled
- Frequency: 5 minutes
- Lookback: 3 hours
- Severity: High/Critical depending on resource importance
- Suggested MITRE: Defense Evasion, Privilege Escalation

Expected noise:
Low to medium, mostly from legitimate admin operations if not allow-listed.

How to tune:
- Exclude approved admin identities and IPs
- Exclude change windows or automation accounts
- Raise severity only for critical subscriptions or monitoring resources

================================================================================
8) BANK-SPN-DORMANT-008
Rule name:
BANK-SPN-DORMANT-008 - Dormant or First-Seen Service Principal Reactivated for Sensitive API Use

KQL:
let HistoricalSP =
    AADServicePrincipalSignInLogs
    | where TimeGenerated between (ago(30d) .. ago(2d))
    | where ResultType == 0
    | summarize LastHistoricalSeen=max(TimeGenerated), SPName=any(ServicePrincipalName) by AppId, ServicePrincipalId;
let RecentSP =
    AADServicePrincipalSignInLogs
    | where TimeGenerated >= ago(2d)
    | where ResultType == 0
    | summarize FirstRecentSeen=min(TimeGenerated), RecentIPs=make_set(IPAddress,10), SPName=any(ServicePrincipalName) by AppId, ServicePrincipalId;
let SensitiveGraph =
    MicrosoftGraphActivityLogs
    | where TimeGenerated >= ago(2d)
    | where ResponseStatusCode between (200 .. 299)
    | where RequestUri has_any ("/users","/groups","/roleManagement","/auditLogs","/applications","/servicePrincipals","/sites","/drives","/messages")
    | summarize Calls=count(), DistinctEndpoints=dcount(RequestUri), Endpoints=make_set(RequestUri, 20), FirstCall=min(TimeGenerated), LastCall=max(TimeGenerated)
      by AppId, ServicePrincipalId
    | where Calls >= 75 and DistinctEndpoints >= 5;
RecentSP
| join kind=leftouter HistoricalSP on AppId, ServicePrincipalId
| join kind=inner SensitiveGraph on AppId, ServicePrincipalId
| where isnull(LastHistoricalSeen) or LastHistoricalSeen < ago(14d)
| where FirstCall between (FirstRecentSeen .. FirstRecentSeen + 12h)
| extend ReactivationType = iff(isnull(LastHistoricalSeen), "FirstSeen", "DormantReactivated")
| extend Score = 60
| project ReactivationType, AppId, ServicePrincipalId, SPName, FirstRecentSeen, RecentIPs, FirstCall, LastCall, Calls, DistinctEndpoints, Endpoints, Score

Explanation:
Detects a service principal that was dormant or never previously seen and is now actively using sensitive Graph APIs.

Tables connection:
- AADServicePrincipalSignInLogs provides historical and recent usage
- MicrosoftGraphActivityLogs confirms sensitive post-auth API activity

Impact:
High. This often indicates secret theft, unmanaged app activation, or abused automation.

Why needed:
Dormant or first-seen non-human identities are dangerous because they evade user-centric monitoring.

Rule config:
- Recommended engine: Sentinel Scheduled
- Frequency: 15 minutes
- Lookback: 2 days
- Severity: High
- Suggested MITRE: Persistence, Collection, Exfiltration

Expected noise:
Usually low.

How to tune:
- Maintain approved automation identities inventory
- Increase dormancy window for stable enterprises
- Restrict sensitive endpoint list to mail, roles, files, and applications

================================================================================
9) BANK-SAAS-ADMIN-009
Rule name:
BANK-SAAS-ADMIN-009 - Uncommon SaaS Admin Operation With Risky Identity Context

KQL:
let UncommonAdmin =
    CloudAppEvents
    | where Timestamp >= ago(12h)
    | where IsAdminOperation == true
    | where tostring(UncommonForUser) =~ "True"
    | project EventTime=Timestamp, AccountDisplayName, AccountId, Application, ActionType, IPAddress, CountryCode, City, UserAgent;
let RiskySignin =
    SigninLogs
    | where TimeGenerated >= ago(12h)
    | where ResultType == 0
    | where IsRisky == true or RiskLevelDuringSignIn in~ ("high","medium")
    | project SigninTime=TimeGenerated, UPN=UserPrincipalName, SigninIP=IPAddress, RiskLevelDuringSignIn;
let PriorAlerts =
    SecurityAlert
    | where TimeGenerated >= ago(7d)
    | summarize PriorAlertCount=count(), AlertNames=make_set(AlertName,10) by CompromisedEntity;
UncommonAdmin
| join kind=leftouter RiskySignin on $left.AccountDisplayName == $right.UPN
| where isnull(SigninTime) or EventTime between (SigninTime .. SigninTime + 8h)
| join kind=leftouter PriorAlerts on $left.AccountDisplayName == $right.CompromisedEntity
| extend Score =
    35
    + iff(isnotempty(SigninTime), 20, 0)
    + iff(PriorAlertCount > 0, 15, 0)
| where Score >= 45
| project EventTime, AccountDisplayName, AccountId, Application, ActionType, IPAddress, CountryCode, City, UserAgent, SigninTime, SigninIP, RiskLevelDuringSignIn, PriorAlertCount, AlertNames, Score

Explanation:
Detects unusual administrative action in SaaS or cloud apps, strengthened by risky sign-in or prior alert context.

Tables connection:
- CloudAppEvents provides SaaS admin activity
- SigninLogs provides risky Entra sign-in context
- SecurityAlert adds provider alert history

Impact:
High. This can indicate compromised admin access in connected SaaS or cloud platforms.

Why needed:
SaaS abuse is often missed when focus stays only on Azure and M365 core telemetry.

Rule config:
- Recommended engine: Defender Custom Detection
- Frequency: 15 minutes
- Lookback: 12 hours
- Severity: High
- Suggested MITRE: Persistence, Privilege Escalation, Defense Evasion

Expected noise:
Medium if many admins use multiple SaaS tools.

How to tune:
- Keep admin role inventory for SaaS platforms
- Exclude known admin maintenance actions
- Focus on high-risk applications and unusual locations

================================================================================
10) BANK-CAMPAIGN-010
Rule name:
BANK-CAMPAIGN-010 - Malicious Mail Campaign With at Least One Real Compromise

KQL:
let Campaign =
    EmailEvents
    | where Timestamp >= ago(24h)
    | where DeliveryAction !in~ ("Blocked","Dropped","Rejected")
    | where ThreatTypes has_any ("Phish","Malware","Spam")
    | summarize Recipients=dcount(RecipientEmailAddress), RecipientList=make_set(RecipientEmailAddress, 50), MsgCount=count()
      by SenderFromAddress, Subject, ThreatTypes
    | where Recipients >= 10 or MsgCount >= 20;
let Clicks =
    UrlClickEvents
    | where Timestamp >= ago(24h)
    | summarize ClickUsers=dcount(AccountUpn), ClickUserList=make_set(AccountUpn, 20), FirstClick=min(Timestamp)
      by NetworkMessageId;
let MailMap =
    EmailEvents
    | where Timestamp >= ago(24h)
    | project NetworkMessageId, SenderFromAddress, Subject, RecipientEmailAddress;
let RiskySignin =
    SigninLogs
    | where TimeGenerated >= ago(24h)
    | where ResultType == 0
    | where IsRisky == true or RiskLevelDuringSignIn in~ ("high","medium")
    | project UPN=UserPrincipalName, SigninTime=TimeGenerated;
let SuspiciousExec =
    DeviceProcessEvents
    | where Timestamp >= ago(24h)
    | where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe")
       or ProcessCommandLine has_any ("-enc","-encodedcommand","DownloadString(","IEX(")
    | project AccountUpn=InitiatingProcessAccountUpn, ProcTime=Timestamp, DeviceName, FileName, ProcessCommandLine;
Campaign
| join kind=inner (
    MailMap
    | join kind=leftouter Clicks on NetworkMessageId
) on SenderFromAddress, Subject
| join kind=leftouter RiskySignin on $left.RecipientEmailAddress == $right.UPN
| join kind=leftouter SuspiciousExec on $left.RecipientEmailAddress == $right.AccountUpn
| extend HasRealCompromise = iff(isnotempty(SigninTime) or isnotempty(ProcTime), 1, 0)
| summarize Recipients=max(Recipients), MsgCount=max(MsgCount), ClickUsers=dcountif(RecipientEmailAddress, isnotempty(FirstClick)),
            CompromisedUsers=dcountif(RecipientEmailAddress, HasRealCompromise == 1),
            ExampleUsers=make_set(RecipientEmailAddress, 20)
  by SenderFromAddress, Subject, ThreatTypes
| where CompromisedUsers >= 1
| project SenderFromAddress, Subject, ThreatTypes, Recipients, MsgCount, ClickUsers, CompromisedUsers, ExampleUsers

Explanation:
Compresses mail alert noise into a campaign-level detection, but only when at least one recipient shows likely compromise behavior.

Tables connection:
- EmailEvents identifies campaign spread
- UrlClickEvents shows engagement
- SigninLogs shows suspicious follow-on sign-in
- DeviceProcessEvents shows endpoint execution

Impact:
Medium to high depending on affected user count and role.

Why needed:
Mail security telemetry can be extremely noisy. Campaign compression is critical for analyst efficiency.

Rule config:
- Recommended engine: Defender Custom Detection or Sentinel
- Frequency: 30 minutes
- Lookback: 24 hours
- Severity: Medium/High
- Suggested use: SOC campaign triage and escalation

Expected noise:
Medium if threat verdicts are broad or spam-heavy.

How to tune:
- Restrict to Phish and Malware if Spam volume is overwhelming
- Require click or compromise thresholds
- Focus on finance, treasury, or executive populations

================================================================================
11) BANK-META-IDENTITY-011
Rule name:
BANK-META-IDENTITY-011 - Composite Identity Compromise Score

KQL:
let RiskSignals =
    SigninLogs
    | where TimeGenerated >= ago(24h)
    | where ResultType == 0 and (IsRisky == true or RiskLevelDuringSignIn in~ ("high","medium"))
    | summarize RiskSignals=count(), LastRisk=max(TimeGenerated) by UPN=UserPrincipalName;
let AuditSignals =
    AuditLogs
    | where ActivityDateTime >= ago(24h)
    | where ActivityDisplayName has_any (
        "Add member to role","Grant consent to application","Add service principal credentials",
        "Register security info","Delete security info","Update authentication method"
    )
    | extend Actor=tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
    | summarize AuditSignals=count(), AuditActions=make_set(ActivityDisplayName,10), LastAudit=max(ActivityDateTime) by UPN=Actor;
let MailSignals =
    OfficeActivity
    | where TimeGenerated >= ago(24h)
    | where OfficeWorkload == "Exchange"
    | where Operation in~ ("New-InboxRule","Set-InboxRule","Set-Mailbox")
    | where Parameters has_any ("ForwardTo","RedirectTo","ForwardingSmtpAddress")
    | summarize MailSignals=count(), LastMail=max(TimeGenerated) by UPN=UserId;
let AzureSignals =
    AzureActivity
    | where TimeGenerated >= ago(24h)
    | where ActivityStatusValue =~ "Succeeded"
    | where OperationNameValue has_any ("ROLEASSIGNMENTS/WRITE","DIAGNOSTICSETTINGS/DELETE","POLICYEXEMPTIONS/WRITE")
    | summarize AzureSignals=count(), LastAzure=max(TimeGenerated) by UPN=Caller;
let PriorAlerts =
    SecurityAlert
    | where TimeGenerated >= ago(24h)
    | summarize PriorAlerts=count(), AlertTitles=make_set(AlertName,10) by UPN=CompromisedEntity;
RiskSignals
| join kind=fullouter AuditSignals on UPN
| join kind=fullouter MailSignals on UPN
| join kind=fullouter AzureSignals on UPN
| join kind=leftouter PriorAlerts on UPN
| extend TotalScore =
    0
    + iff(RiskSignals >= 1, 20, 0)
    + iff(AuditSignals >= 1, 20, 0)
    + iff(MailSignals >= 1, 20, 0)
    + iff(AzureSignals >= 1, 20, 0)
    + iff(PriorAlerts >= 1, 10, 0)
| where TotalScore >= 45
| project UPN, TotalScore, RiskSignals, AuditSignals, MailSignals, AzureSignals, PriorAlerts, AlertTitles, LastRisk, LastAudit, LastMail, LastAzure, AuditActions
| order by TotalScore desc

Explanation:
A meta-correlation rule that scores likely identity compromise across multiple Microsoft signals.

Tables connection:
- SigninLogs for risky authentication
- AuditLogs for privileged or persistence activity
- OfficeActivity for mailbox persistence
- AzureActivity for cloud control-plane impact
- SecurityAlert for prior provider-confirmed context

Impact:
High. This is a prioritization rule that helps the SOC focus on the most suspicious identities.

Why needed:
Organizations often suffer from incident sprawl. Composite scoring helps convert many weak signals into a manageable queue.

Rule config:
- Recommended engine: Sentinel Scheduled
- Frequency: 15 minutes
- Lookback: 24 hours
- Severity: Tiered by score
- Suggested use: Triage, prioritization, escalation

Expected noise:
Medium if many signals are generated by legitimate admins or automation.

How to tune:
- Weight privileged or finance users more heavily
- Add break-glass exclusions
- Raise threshold if environment is especially dynamic
- Add IdentityInfo and BehaviorAnalytics for better scoring

================================================================================
12) BANK-ENDPOINT-PERSIST-012
Rule name:
BANK-ENDPOINT-PERSIST-012 - Endpoint Persistence Added on Server/VM With External Network Activity

KQL:
let Persistence =
    DeviceRegistryEvents
    | where Timestamp >= ago(12h)
    | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
    | where RegistryKey has_any (
        @"\Software\Microsoft\Windows\CurrentVersion\Run",
        @"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    )
    | project PersistTime=Timestamp, DeviceId, DeviceName, AccountUpn=InitiatingProcessAccountUpn, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine;
let ExternalNet =
    DeviceNetworkEvents
    | where Timestamp >= ago(12h)
    | where RemoteIPType == "Public" or isnotempty(RemoteUrl)
    | project NetTime=Timestamp, DeviceId, RemoteIP, RemoteUrl, InitiatingProcessFileName;
Persistence
| join kind=inner ExternalNet on DeviceId
| where NetTime between (PersistTime .. PersistTime + 2h)
| extend Score = 55
| project PersistTime, NetTime, DeviceName, AccountUpn, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, Score

Explanation:
Detects local persistence added to a Windows endpoint or server and then followed by external network activity.

Tables connection:
- DeviceRegistryEvents shows persistence via registry
- DeviceNetworkEvents shows public-facing communication afterward

Impact:
High on servers and VMs. This often indicates malware persistence with likely command and control.

Why needed:
Persistence alone may be noisy. Persistence plus external communication is much stronger.

Rule config:
- Recommended engine: Defender Custom Detection
- Frequency: 15 minutes
- Lookback: 12 hours
- Severity: High on servers / Medium on workstations
- Suggested MITRE: Persistence, Command and Control

Expected noise:
Medium on IT-admin-heavy endpoints, low on locked-down servers.

How to tune:
- Exclude known software updaters and enterprise agents
- Apply only to server classes or critical device groups
- Add process allowlists for approved tools

================================================================================
13) ENTRA-PRIV-CHAIN-01
Rule name:
ENTRA-PRIV-CHAIN-01 - Risky sign-in → privileged role assignment

KQL:
let RiskySignin =
SigninLogs
| where TimeGenerated >= ago(2h)
| where ResultType == 0
| where IsRisky == true or RiskLevelDuringSignIn in~ ("medium","high")
| project SigninTime=TimeGenerated, UPN=UserPrincipalName, IPAddress, RiskLevelDuringSignIn, AppDisplayName;
let RoleChange =
AuditLogs
| where ActivityDateTime >= ago(2h)
| where ActivityDisplayName has_any ("Add member to role","Add eligible member to role","Add member to directory role")
| extend Actor=tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| project AuditTime=ActivityDateTime, Actor, ActivityDisplayName, TargetResources, CorrelationId;
let IdCtx =
IdentityInfo
| summarize arg_max(TimeGenerated, *) by AccountUPN
| project AccountUPN, BlastRadius, InvestigationPriority, AssignedRoles;
RiskySignin
| join kind=inner RoleChange on $left.UPN == $right.Actor
| where AuditTime between (SigninTime .. SigninTime + 60m)
| join kind=leftouter IdCtx on $left.UPN == $right.AccountUPN
| extend Score=50 + iff(RiskLevelDuringSignIn =~ "high",15,8) + iff(BlastRadius =~ "High",15,0)
| where Score >= 60

Explanation:
Correlates risky authentication with privileged role assignment.

Tables connection:
SigninLogs + AuditLogs + IdentityInfo

Impact:
High. Strong privilege escalation path.

Why needed:
Role assignments after risky sign-ins are high-priority events in cloud identity compromise.

Expected noise:
Low to medium depending on privileged admin activity.

How to tune:
Use allowlists for admin workflows and approved emergency changes.

Rule config:
Recommended engine: Sentinel Scheduled
Frequency: 5 minutes
Lookback: 2 hours
Severity: High

================================================================================
14) ENTRA-PRIV-CHAIN-02
Rule name:
ENTRA-PRIV-CHAIN-02 - Risky sign-in → MFA / authentication method tampering

KQL:
let RiskySignin =
SigninLogs
| where TimeGenerated >= ago(2h)
| where ResultType == 0
| where IsRisky == true or RiskLevelDuringSignIn in~ ("medium","high")
| project SigninTime=TimeGenerated, UPN=UserPrincipalName, IPAddress, RiskLevelDuringSignIn;
let AuthMethodChange =
AuditLogs
| where ActivityDateTime >= ago(2h)
| where ActivityDisplayName has_any ("Register security info","Delete security info","Update authentication method")
| extend Actor=tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| project AuditTime=ActivityDateTime, Actor, ActivityDisplayName, CorrelationId, Result;
RiskySignin
| join kind=inner AuthMethodChange on $left.UPN == $right.Actor
| where AuditTime between (SigninTime .. SigninTime + 45m)
| extend Score=55 + iff(RiskLevelDuringSignIn =~ "high",10,0)
| where Score >= 55

Explanation:
Detects risky sign-in immediately followed by authentication method tampering.

Tables connection:
SigninLogs + AuditLogs

Impact:
Very high. This is a common persistence move after account takeover.

Why needed:
Authentication method changes directly affect account recovery and persistence.

Expected noise:
Low for most users, medium for legitimate onboarding events.

How to tune:
Exclude new-user onboarding processes and approved security registrations.

Rule config:
Recommended engine: Sentinel Scheduled
Frequency: 5 minutes
Lookback: 2 hours
Severity: High

================================================================================
15) ENTRA-OAUTH-CHAIN-03
Rule name:
ENTRA-OAUTH-CHAIN-03 - OAuth consent / secret add → service principal sign-in → Graph sensitive enumeration

KQL:
let Establish =
AuditLogs
| where ActivityDateTime >= ago(6h)
| where ActivityDisplayName has_any (
    "Grant consent to application",
    "Consent to application",
    "Add service principal credentials",
    "Update application - Certificates and secrets management"
)
| extend TargetApp=tostring(TargetResources[0].displayName)
| extend Initiator=tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| project EstablishTime=ActivityDateTime, TargetApp, Initiator, ActivityDisplayName, CorrelationId;
let SpnSignin =
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(6h)
| where ResultType == 0
| summarize FirstSPN=min(TimeGenerated), SPNIPs=make_set(IPAddress,10), SPNNames=make_set(ServicePrincipalName,5) by AppId, ServicePrincipalId;
let GraphBurst =
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(6h)
| where ResponseStatusCode between (200 .. 299)
| where RequestUri has_any ("/users","/groups","/directoryRoles","/roleManagement","/messages","/sites","/drives","/applications","/servicePrincipals")
| summarize GraphCalls=count(), DistinctUris=dcount(RequestUri), FirstGraph=min(TimeGenerated), Uris=make_set(RequestUri,20) by AppId, ServicePrincipalId
| where GraphCalls >= 40 and DistinctUris >= 5;
GraphBurst
| join kind=inner SpnSignin on AppId, ServicePrincipalId
| join kind=inner Establish on $left.SPNNames has $right.TargetApp
| where FirstGraph between (EstablishTime .. EstablishTime + 2h) or FirstSPN between (EstablishTime .. EstablishTime + 2h)

Explanation:
A concise app-abuse correlation linking app establishment to app authentication and Graph usage.

Tables connection:
AuditLogs + AADServicePrincipalSignInLogs + MicrosoftGraphActivityLogs

Impact:
High.

Why needed:
App abuse is durable and stealthy.

Expected noise:
Low.

How to tune:
App allowlists, tighter endpoint scope, stronger AppId parsing.

Rule config:
Recommended engine: Sentinel Scheduled
Frequency: 10 minutes
Lookback: 6 hours
Severity: High

================================================================================
16) ENTRA-SPN-04
Rule name:
ENTRA-SPN-04 - Dormant/new service principal reactivated for sensitive APIs

KQL:
let Hist =
AADServicePrincipalSignInLogs
| where TimeGenerated between (ago(30d) .. ago(2d))
| where ResultType == 0
| summarize LastSeen=max(TimeGenerated), SPNName=any(ServicePrincipalName) by AppId, ServicePrincipalId;
let Recent =
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(2d)
| where ResultType == 0
| summarize FirstSeen=min(TimeGenerated), RecentIPs=make_set(IPAddress,10), SPNName=any(ServicePrincipalName) by AppId, ServicePrincipalId;
let GraphUse =
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(2d)
| where ResponseStatusCode between (200 .. 299)
| where RequestUri has_any ("/users","/groups","/roleManagement","/auditLogs","/mailFolders","/messages","/sites","/drives")
| summarize Calls=count(), DistinctEndpoints=dcount(RequestUri), FirstCall=min(TimeGenerated), Endpoints=make_set(RequestUri,20) by AppId, ServicePrincipalId
| where Calls >= 75 and DistinctEndpoints >= 5;
Recent
| join kind=leftouter Hist on AppId, ServicePrincipalId
| join kind=inner GraphUse on AppId, ServicePrincipalId
| where isnull(LastSeen) or LastSeen < ago(14d)
| where FirstCall between (FirstSeen .. FirstSeen + 12h)

Explanation:
Baseline-based detection for dormant or unseen service principals.

Tables connection:
AADServicePrincipalSignInLogs + MicrosoftGraphActivityLogs

Impact:
High.

Why needed:
Dormant app identities are a common overlooked attack surface.

Expected noise:
Low.

How to tune:
Increase dormancy duration or maintain approved service principal inventory.

Rule config:
Recommended engine: Sentinel Scheduled
Frequency: 15 minutes
Lookback: 2 days
Severity: High

================================================================================
17) ENTRA-MI-05
Rule name:
ENTRA-MI-05 - Managed identity sign-in anomaly → Azure control-plane write

KQL:
let MIRecent =
AADManagedIdentitySignInLogs
| where TimeGenerated >= ago(6h)
| where ResultType == 0
| summarize FirstSeen=min(TimeGenerated), IPs=make_set(IPAddress,10) by ServicePrincipalId, Identity;
let HistMI =
AADManagedIdentitySignInLogs
| where TimeGenerated between (ago(30d) .. ago(2d))
| where ResultType == 0
| summarize LastSeen=max(TimeGenerated) by ServicePrincipalId;
let CtrlWrites =
AzureActivity
| where TimeGenerated >= ago(6h)
| where ActivityStatusValue =~ "Succeeded"
| where OperationNameValue has_any ("MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE","MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE","MICROSOFT.AUTHORIZATION/POLICYEXEMPTIONS/WRITE")
| project ActivityTime=TimeGenerated, Caller, OperationNameValue, ResourceId, SubscriptionId;
MIRecent
| join kind=leftouter HistMI on ServicePrincipalId
| join kind=inner CtrlWrites on $left.Identity == $right.Caller
| where isnull(LastSeen) or LastSeen < ago(14d)
| where ActivityTime between (FirstSeen .. FirstSeen + 4h)

Explanation:
Looks for new or dormant managed identity use followed by control-plane changes.

Tables connection:
AADManagedIdentitySignInLogs + AzureActivity

Impact:
High.

Why needed:
Managed identities are often invisible to user-focused monitoring.

Expected noise:
Low.

How to tune:
Exclude deployment windows and known pipeline identities.

Rule config:
Recommended engine: Sentinel Scheduled
Frequency: 10 minutes
Lookback: 6 hours
Severity: High

================================================================================
18) AZ-CTRL-06
Rule name:
AZ-CTRL-06 - Risky user sign-in → role assignment / policy exemption / diagnostic deletion

KQL:
let SuspiciousSignin =
SigninLogs
| where TimeGenerated >= ago(3h)
| where ResultType == 0
| where IsRisky == true or RiskLevelDuringSignIn in~ ("medium","high")
| project SigninTime=TimeGenerated, UPN=UserPrincipalName, IPAddress, RiskLevelDuringSignIn;
let DangerousCtrl =
AzureActivity
| where TimeGenerated >= ago(3h)
| where ActivityStatusValue =~ "Succeeded"
| where OperationNameValue has_any (
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
    "MICROSOFT.AUTHORIZATION/POLICYEXEMPTIONS/WRITE",
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE"
)
| project ActivityTime=TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceId;
SuspiciousSignin
| join kind=inner DangerousCtrl on $left.UPN == $right.Caller
| where ActivityTime between (SigninTime .. SigninTime + 90m)

Explanation:
A concise Azure control-plane abuse correlation.

Tables connection:
SigninLogs + AzureActivity

Impact:
High.

Why needed:
Captures privileged cloud actions after suspicious user authentication.

Expected noise:
Medium in admin-heavy subscriptions.

How to tune:
Restrict to critical resource groups and approved admin exclusion sets.

Rule config:
Recommended engine: Sentinel Scheduled
Frequency: 5 minutes
Lookback: 3 hours
Severity: High

================================================================================
19) AZ-EXPOSURE-07
Rule name:
AZ-EXPOSURE-07 - Suspicious sign-in → NSG opens SSH/RDP/WinRM to Internet

KQL:
let SuspiciousSignin =
SigninLogs
| where TimeGenerated >= ago(3h)
| where ResultType == 0
| where IsRisky == true or RiskLevelDuringSignIn in~ ("medium","high")
| project SigninTime=TimeGenerated, UPN=UserPrincipalName;
let NsgOpen =
AzureActivity
| where TimeGenerated >= ago(3h)
| where ActivityStatusValue =~ "Succeeded"
| where OperationNameValue has_any ("MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE","MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE")
| where Properties has_any ("3389","22","5985","5986")
| where Properties has_any ("0.0.0.0/0","*","Internet","Any")
| project ActivityTime=TimeGenerated, Caller, ResourceId, Properties;
SuspiciousSignin
| join kind=inner NsgOpen on $left.UPN == $right.Caller
| where ActivityTime between (SigninTime .. SigninTime + 2h)

Explanation:
Detects management-plane internet exposure following a suspicious login.

Tables connection:
SigninLogs + AzureActivity

Impact:
High to critical depending on resource type.

Why needed:
Opening management ports to the world is a common post-compromise action.

Expected noise:
Low if focused only on public management ports.

How to tune:
Exclude known change windows or approved infrastructure deployment accounts.

Rule config:
Recommended engine: Sentinel Scheduled
Frequency: 10 minutes
Lookback: 3 hours
Severity: High

================================================================================
20) M365-BEC-08
Rule name:
M365-BEC-08 - Delivered phish → click → cloud sign-in → mailbox forwarding

KQL:
let Phish =
EmailEvents
| where Timestamp >= ago(24h)
| where DeliveryAction !in~ ("Blocked","Dropped","Rejected")
| where ThreatTypes has_any ("Phish","Malware")
| project MsgTime=Timestamp, Recipient=RecipientEmailAddress, NetworkMessageId, Sender=SenderFromAddress, Subject;
let Clicks =
UrlClickEvents
| where Timestamp >= ago(24h)
| summarize FirstClick=min(Timestamp), Urls=make_set(Url,10) by NetworkMessageId, AccountUpn;
let Signins =
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == 0
| project SigninTime=TimeGenerated, UPN=UserPrincipalName, IPAddress, IsRisky, RiskLevelDuringSignIn;
let Forwarding =
OfficeActivity
| where TimeGenerated >= ago(24h)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("Set-Mailbox","New-InboxRule","Set-InboxRule")
| where Parameters has_any ("ForwardingSmtpAddress","ForwardTo","RedirectTo","DeliverToMailboxAndForward")
| project TamperTime=TimeGenerated, UserId, Operation, Parameters;
Phish
| join kind=inner Clicks on NetworkMessageId
| join kind=inner Signins on $left.Recipient == $right.UPN
| where SigninTime between (FirstClick .. FirstClick + 6h)
| join kind=inner Forwarding on $left.Recipient == $right.UserId
| where TamperTime between (SigninTime .. SigninTime + 6h)

Explanation:
A concise BEC chain.

Tables connection:
EmailEvents + UrlClickEvents + SigninLogs + OfficeActivity

Impact:
High.

Why needed:
High-confidence email compromise path.

Expected noise:
Low.

How to tune:
Focus on external forwarding and finance-related users.

Rule config:
Recommended engine: Defender or Sentinel
Frequency: 15 minutes
Lookback: 24 hours
Severity: High

================================================================================
21) M365-CAMPAIGN-09
Rule name:
M365-CAMPAIGN-09 - Phishing campaign → multiple recipients → click(s) → at least one real compromise

KQL:
let Campaign =
EmailEvents
| where Timestamp >= ago(24h)
| where DeliveryAction !in~ ("Blocked","Dropped","Rejected")
| where ThreatTypes has_any ("Phish","Malware")
| summarize Recipients=dcount(RecipientEmailAddress), MsgIds=make_set(NetworkMessageId,100) by SenderFromAddress, Subject
| where Recipients >= 5;
let Clicks =
UrlClickEvents
| where Timestamp >= ago(24h)
| summarize ClickUsers=dcount(AccountUpn), ClickUrls=make_set(Url,20) by NetworkMessageId;
let Compromise =
OfficeActivity
| where TimeGenerated >= ago(24h)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("New-InboxRule","Set-InboxRule","Set-Mailbox")
| where Parameters has_any ("ForwardingSmtpAddress","ForwardTo","RedirectTo")
| summarize CompUsers=dcount(UserId), Users=make_set(UserId,20) by UserId;
EmailEvents
| where Timestamp >= ago(24h)
| where DeliveryAction !in~ ("Blocked","Dropped","Rejected")
| where ThreatTypes has_any ("Phish","Malware")
| join kind=inner Campaign on SenderFromAddress, Subject
| join kind=leftouter Clicks on NetworkMessageId
| summarize TotalRecipients=dcount(RecipientEmailAddress), ClickedUsers=sumif(1, ClickUsers > 0) by SenderFromAddress, Subject
| where TotalRecipients >= 5 and ClickedUsers >= 1

Explanation:
Detects malicious campaigns with actual evidence of engagement.

Tables connection:
EmailEvents + UrlClickEvents + OfficeActivity

Impact:
Medium to High.

Why needed:
Campaign-level detections reduce analyst overload.

Expected noise:
Medium.

How to tune:
Use stricter thresholds and only alert if at least one user later shows persistence.

Rule config:
Recommended engine: Defender or Sentinel
Frequency: 30 minutes
Lookback: 24 hours
Severity: Medium/High

================================================================================
22) M365-OAUTH-MAIL-10
Rule name:
M365-OAUTH-MAIL-10 - Mailbox forwarding + OAuth consent by same user

KQL:
let MailForward =
OfficeActivity
| where TimeGenerated >= ago(12h)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("Set-Mailbox","New-InboxRule","Set-InboxRule")
| where Parameters has_any ("ForwardingSmtpAddress","ForwardTo","RedirectTo")
| project FwdTime=TimeGenerated, UserId;
let Consent =
AuditLogs
| where ActivityDateTime >= ago(12h)
| where ActivityDisplayName has_any ("Grant consent to application","Consent to application")
| extend Actor=tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| project ConsentTime=ActivityDateTime, Actor, ActivityDisplayName;
MailForward
| join kind=inner Consent on $left.UserId == $right.Actor
| where ConsentTime between (FwdTime - 2h .. FwdTime + 2h)

Explanation:
Detects dual persistence: mailbox forwarding and OAuth consent by the same identity.

Tables connection:
OfficeActivity + AuditLogs

Impact:
High.

Why needed:
Multiple persistence methods on one identity dramatically increase compromise confidence.

Expected noise:
Low.

How to tune:
Exclude authorized forwarding or known app onboarding users.

Rule config:
Recommended engine: Sentinel Scheduled
Frequency: 15 minutes
Lookback: 12 hours
Severity: High

================================================================================
23) M365-DATA-11
Rule name:
M365-DATA-11 - Suspicious sign-in → SharePoint/OneDrive mass download

KQL:
let SuspiciousSignin =
SigninLogs
| where TimeGenerated >= ago(12h)
| where ResultType == 0
| where IsRisky == true or RiskLevelDuringSignIn in~ ("medium","high")
| project SigninTime=TimeGenerated, UPN=UserPrincipalName, IPAddress;
let DownloadBurst =
OfficeActivity
| where TimeGenerated >= ago(12h)
| where OfficeWorkload in ("SharePoint","OneDrive")
| where Operation in ("FileDownloaded","FileSyncDownloadedFull","FileSyncDownloadedPartial","FileAccessed")
| summarize FileOps=count(), DistinctFiles=dcount(OfficeObjectId), FirstOp=min(TimeGenerated), Sites=make_set(Site_Url,10) by UserId
| where FileOps >= 150 and DistinctFiles >= 60;
SuspiciousSignin
| join kind=inner DownloadBurst on $left.UPN == $right.UserId
| where FirstOp between (SigninTime .. SigninTime + 4h)

Explanation:
Detects likely data staging or exfiltration after suspicious sign-in.

Tables connection:
SigninLogs + OfficeActivity

Impact:
High.

Why needed:
Data theft risk is high in finance environments.

Expected noise:
Medium if users routinely sync large data sets.

How to tune:
Exclude approved backup or sync users
Separate file access from download operations
Raise thresholds by department

Rule config:
Recommended engine: Sentinel Scheduled
Frequency: 15 minutes
Lookback: 12 hours
Severity: High

================================================================================
24) M365-TRAVEL-12
Rule name:
M365-TRAVEL-12 - Country switch + mail/file actions in short window

KQL:
let FirstCountry =
SigninLogs
| where TimeGenerated >= ago(12h)
| where ResultType == 0
| summarize FirstTime=min(TimeGenerated), FirstCountry=any(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName;
let SecondCountry =
SigninLogs
| where TimeGenerated >= ago(12h)
| where ResultType == 0
| summarize LastTime=max(TimeGenerated), LastCountry=any(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName;
let CloudOps =
OfficeActivity
| where TimeGenerated >= ago(12h)
| where OfficeWorkload in ("Exchange","SharePoint","OneDrive","Teams")
| summarize CloudActions=count(), FirstCloud=min(TimeGenerated) by UserId;
FirstCountry
| join kind=inner SecondCountry on UserPrincipalName
| join kind=inner CloudOps on $left.UserPrincipalName == $right.UserId
| where FirstCountry != LastCountry
| where LastTime - FirstTime < 4h
| where FirstCloud between (LastTime .. LastTime + 2h)

Explanation:
Detects rapid country change followed by cloud actions.

Tables connection:
SigninLogs + OfficeActivity

Impact:
Medium to high depending on account sensitivity.

Why needed:
Adds impact to location-based anomalies.

Expected noise:
Medium due to VPNs and travel.

How to tune:
Exclude known corporate VPN ranges
Restrict to high-value users
Combine with risk signals

Rule config:
Recommended engine: Sentinel Scheduled
Frequency: 30 minutes
Lookback: 12 hours
Severity: Medium/High

================================================================================
25) XDR-CLOUD-PIVOT-13
Rule name:
XDR-CLOUD-PIVOT-13 - Office/browser child process → external network → cloud persistence

KQL:
let SuspiciousProc =
DeviceProcessEvents
| where Timestamp >= ago(6h)
| where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE","chrome.exe","msedge.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe")
   or ProcessCommandLine has_any ("-enc","-encodedcommand","FromBase64String","DownloadString(","IEX(","http://","https://")
| project ProcTime=Timestamp, DeviceId, DeviceName, AccountUpn=InitiatingProcessAccountUpn, FileName, ProcessCommandLine;
let Net =
DeviceNetworkEvents
| where Timestamp >= ago(6h)
| where RemoteIPType == "Public" or isnotempty(RemoteUrl)
| project NetTime=Timestamp, DeviceId, RemoteIP, RemoteUrl, InitiatingProcessFileName;
let CloudPersist =
union isfuzzy=true
(
    AuditLogs
    | where ActivityDateTime >= ago(6h)
    | where ActivityDisplayName has_any ("Grant consent to application","Register security info","Delete security info","Update authentication method")
    | extend Actor=tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
    | project CloudTime=ActivityDateTime, Actor, ChangeType=ActivityDisplayName
),
(
    OfficeActivity
    | where TimeGenerated >= ago(6h)
    | where OfficeWorkload == "Exchange"
    | where Operation in~ ("Set-Mailbox","New-InboxRule","Set-InboxRule")
    | where Parameters has_any ("ForwardingSmtpAddress","ForwardTo","RedirectTo")
    | project CloudTime=TimeGenerated, Actor=UserId, ChangeType=Operation
);
SuspiciousProc
| join kind=inner Net on DeviceId
| where NetTime between (ProcTime .. ProcTime + 30m)
| join kind=inner CloudPersist on $left.AccountUpn == $right.Actor
| where CloudTime between (NetTime .. NetTime + 4h)

Explanation:
Cross-domain detection for endpoint compromise pivoting into cloud persistence.

Tables connection:
DeviceProcessEvents + DeviceNetworkEvents + AuditLogs/OfficeActivity

Impact:
Very high.

Why needed:
Attack chains often cross endpoint and cloud boundaries.

Expected noise:
Low if all three stages are required.

How to tune:
Exclude known admin scripts and automation
Use crown-jewel or finance-user boosts
Require external network only

Rule config:
Recommended engine: Defender Custom Detection
Frequency: 10 minutes
Lookback: 6 hours
Severity: High

================================================================================
26) SERVER-CROWN-14
Rule name:
SERVER-CROWN-14 - Critical server suspicious process + risky user context

KQL:
let Critical =
_GetWatchlist('CriticalServers') | project DeviceName=tostring(SearchKey);
let SuspiciousServerProc =
DeviceProcessEvents
| where Timestamp >= ago(6h)
| where DeviceName in (Critical)
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","psexec.exe","wmic.exe","rundll32.exe","regsvr32.exe")
   or ProcessCommandLine has_any ("-enc","DownloadString(","IEX(","vssadmin","wbadmin","bcdedit","net user","whoami /priv")
| project ProcTime=Timestamp, DeviceName, DeviceId, AccountUpn=InitiatingProcessAccountUpn, FileName, ProcessCommandLine;
let RiskySignin =
SigninLogs
| where TimeGenerated >= ago(12h)
| where ResultType == 0
| where IsRisky == true or RiskLevelDuringSignIn in~ ("medium","high")
| project SigninTime=TimeGenerated, UPN=UserPrincipalName;
SuspiciousServerProc
| join kind=inner RiskySignin on $left.AccountUpn == $right.UPN
| where ProcTime between (SigninTime .. SigninTime + 12h)

Explanation:
A simpler crown-jewel server rule that correlates risky cloud identity with suspicious server activity.

Tables connection:
DeviceProcessEvents + SigninLogs + CriticalServers watchlist

Impact:
Critical for privileged or payment-linked servers.

Why needed:
Crown-jewel systems deserve much more aggressive correlation logic.

Expected noise:
Low if the critical server list is accurate.

How to tune:
Use separate lists for Tier 0, finance, and infrastructure servers.

Rule config:
Recommended engine: Defender Custom Detection
Frequency: 10 minutes
Lookback: 12 hours
Severity: Critical

================================================================================
27) SERVER-LOLBIN-15
Rule name:
SERVER-LOLBIN-15 - Encoded PowerShell / LOLBIN → public network from server or VM

KQL:
let Critical =
_GetWatchlist('CriticalServers') | project DeviceName=tostring(SearchKey);
let SuspiciousExec =
DeviceProcessEvents
| where Timestamp >= ago(6h)
| where DeviceName in (Critical)
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","wscript.exe","cscript.exe")
| where ProcessCommandLine has_any ("-enc","-encodedcommand","FromBase64String","DownloadString(","IEX(","http://","https://","scrobj.dll","urlcache")
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountUpn, FileName, ProcessCommandLine;
let Egress =
DeviceNetworkEvents
| where Timestamp >= ago(6h)
| where RemoteIPType == "Public" or isnotempty(RemoteUrl)
| project NetTime=Timestamp, DeviceId, RemoteIP, RemoteUrl, RemotePort;
SuspiciousExec
| join kind=inner Egress on DeviceId
| where NetTime between (Timestamp .. Timestamp + 20m)

Explanation:
Detects suspicious LOLBIN-style execution on sensitive servers followed by outbound communication.

Tables connection:
DeviceProcessEvents + DeviceNetworkEvents + CriticalServers watchlist

Impact:
High to critical.

Why needed:
Server-side egress after script/LOLBIN abuse is often highly suspicious.

Expected noise:
Low on hardened servers, medium on admin servers.

How to tune:
Exclude approved automation, software distribution, and management tooling.

Rule config:
Recommended engine: Defender Custom Detection
Frequency: 10 minutes
Lookback: 6 hours
Severity: High/Critical

================================================================================
28) XDR-DEFENSE-EVASION-16
Rule name:
XDR-DEFENSE-EVASION-16 - Security control disabled → suspicious execution soon after

KQL:
let Tamper =
DeviceEvents
| where Timestamp >= ago(6h)
| where ActionType has_any ("TamperProtection","Antivirus","RealTimeProtection","ExploitGuard","Firewall")
| where AdditionalFields has_any ("Disable","TurnOff","Stopped","Tamper")
| project TamperTime=Timestamp, DeviceId, DeviceName, AccountName, ActionType, AdditionalFields;
let SuspiciousProc =
DeviceProcessEvents
| where Timestamp >= ago(6h)
| where FileName in~ ("powershell.exe","cmd.exe","reg.exe","wmic.exe","mshta.exe","rundll32.exe")
   or ProcessCommandLine has_any ("Set-MpPreference","sc stop","reg add","DisableRealtimeMonitoring","Add-MpPreference")
| project ProcTime=Timestamp, DeviceId, FileName, ProcessCommandLine;
Tamper
| join kind=inner SuspiciousProc on DeviceId
| where ProcTime between (TamperTime .. TamperTime + 1h)

Explanation:
Detects likely defense evasion followed by suspicious execution.

Tables connection:
DeviceEvents + DeviceProcessEvents

Impact:
High.

Why needed:
Attackers often disable defenses before payload deployment.

Expected noise:
Medium if IT tooling legitimately modifies endpoint protection settings.

How to tune:
Exclude EDR/AV management tools and maintenance windows.

Rule config:
Recommended engine: Defender Custom Detection
Frequency: 15 minutes
Lookback: 6 hours
Severity: High

================================================================================
29) XDR-RANSOM-PRE-17
Rule name:
XDR-RANSOM-PRE-17 - Ransomware precursor: shadow copy disable / backup sabotage → mass file modifications

KQL:
let Sabotage =
DeviceProcessEvents
| where Timestamp >= ago(6h)
| where FileName in~ ("cmd.exe","powershell.exe","wmic.exe","vssadmin.exe","wbadmin.exe","bcdedit.exe")
| where ProcessCommandLine has_any ("vssadmin delete shadows","wmic shadowcopy delete","wbadmin delete catalog","bcdedit /set {default} recoveryenabled no","bcdedit /set {default} bootstatuspolicy ignoreallfailures")
| project SabotageTime=Timestamp, DeviceId, DeviceName, InitiatingProcessAccountUpn, ProcessCommandLine;
let FileBurst =
DeviceFileEvents
| where Timestamp >= ago(6h)
| summarize FileChanges=count(), DistinctFolders=dcount(FolderPath), FirstFile=min(Timestamp) by DeviceId
| where FileChanges >= 500 and DistinctFolders >= 20;
Sabotage
| join kind=inner FileBurst on DeviceId
| where FirstFile between (SabotageTime .. SabotageTime + 90m)

Explanation:
Detects ransomware preparation and likely encryption activity.

Tables connection:
DeviceProcessEvents + DeviceFileEvents

Impact:
Critical.

Why needed:
This can catch ransomware before or during active damage.

Expected noise:
Low.

How to tune:
Exclude backup maintenance utilities and disaster recovery testing windows.

Rule config:
Recommended engine: Defender Custom Detection
Frequency: 10 minutes
Lookback: 6 hours
Severity: Critical

================================================================================
30) SAAS-ADMIN-18
Rule name:
SAAS-ADMIN-18 - Uncommon SaaS admin operation + risky identity context

KQL:
let UncommonAdmin =
CloudAppEvents
| where Timestamp >= ago(12h)
| where IsAdminOperation == true
| where tostring(UncommonForUser) =~ "True"
| project EventTime=Timestamp, AccountDisplayName, AccountId, Application, ActionType, IPAddress, CountryCode, UserAgent, LastSeenForUser;
let RiskySignin =
SigninLogs
| where TimeGenerated >= ago(12h)
| where ResultType == 0
| where IsRisky == true or RiskLevelDuringSignIn in~ ("medium","high")
| project SigninTime=TimeGenerated, UPN=UserPrincipalName, SigninIP=IPAddress;
UncommonAdmin
| join kind=leftouter RiskySignin on $left.AccountDisplayName == $right.UPN
| where isnull(SigninTime) or EventTime between (SigninTime .. SigninTime + 8h)

Explanation:
Simplified SaaS admin abuse correlation.

Tables connection:
CloudAppEvents + SigninLogs

Impact:
High.

Why needed:
Important for connected cloud apps and non-core SaaS services.

Expected noise:
Medium.

How to tune:
Limit to critical apps and high-risk admin actions.

Rule config:
Recommended engine: Defender Custom Detection
Frequency: 15 minutes
Lookback: 12 hours
Severity: High

================================================================================
31) META-IDENTITY-19
Rule name:
META-IDENTITY-19 - Composite identity compromise score

KQL:
let RiskSignals =
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == 0 and (IsRisky == true or RiskLevelDuringSignIn in~ ("medium","high"))
| summarize RiskSignals=count() by UPN=UserPrincipalName;
let AuditSignals =
AuditLogs
| where ActivityDateTime >= ago(24h)
| where ActivityDisplayName has_any ("Add member to role","Grant consent to application","Register security info","Delete security info","Update authentication method")
| extend Actor=tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| summarize AuditSignals=count() by UPN=Actor;
let MailSignals =
OfficeActivity
| where TimeGenerated >= ago(24h)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("Set-Mailbox","New-InboxRule","Set-InboxRule")
| where Parameters has_any ("ForwardTo","RedirectTo","ForwardingSmtpAddress")
| summarize MailSignals=count() by UPN=UserId;
let BA =
BehaviorAnalytics
| where TimeGenerated >= ago(24h)
| summarize MaxPriority=max(InvestigationPriority) by UPN=UserPrincipalName;
RiskSignals
| join kind=fullouter AuditSignals on UPN
| join kind=fullouter MailSignals on UPN
| join kind=fullouter BA on UPN
| extend TotalScore = iff(RiskSignals>=1,20,0)+iff(AuditSignals>=1,20,0)+iff(MailSignals>=1,20,0)+iff(MaxPriority>=7,15,iff(MaxPriority>=4,8,0))
| where TotalScore >= 35

Explanation:
A broad meta-correlation scoring model for user compromise.

Tables connection:
SigninLogs + AuditLogs + OfficeActivity + BehaviorAnalytics

Impact:
High for prioritization.

Why needed:
Useful to condense many identity-related signals into one analyst-friendly queue.

Expected noise:
Medium.

How to tune:
Adjust thresholds and weights by department, criticality, and admin role.

Rule config:
Recommended engine: Sentinel Scheduled
Frequency: 15 minutes
Lookback: 24 hours
Severity: Medium/High

================================================================================
32) META-ENTITY-20
Rule name:
META-ENTITY-20 - User + device + app + alert evidence fusion

KQL:
let Alerts =
SecurityAlert
| where TimeGenerated >= ago(24h)
| summarize AlertCount=count(), AlertNames=make_set(AlertName,10) by CompromisedEntity;
let Evidence =
AlertEvidence
| where Timestamp >= ago(24h)
| summarize EvidenceCount=count(), Entities=make_set(EntityType,10) by AccountUpn, DeviceName;
let DeviceSuspicious =
DeviceProcessEvents
| where Timestamp >= ago(24h)
| where FileName in~ ("powershell.exe","cmd.exe","mshta.exe","rundll32.exe","regsvr32.exe")
   or ProcessCommandLine has_any ("-enc","DownloadString(","IEX(","vssadmin")
| summarize SuspiciousProc=count() by AccountUpn=InitiatingProcessAccountUpn, DeviceName;
let RiskySignin =
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == 0
| where IsRisky == true or RiskLevelDuringSignIn in~ ("medium","high")
| summarize RiskyCount=count() by AccountUpn=UserPrincipalName;
RiskySignin
| join kind=fullouter DeviceSuspicious on AccountUpn
| join kind=leftouter Evidence on AccountUpn, DeviceName
| join kind=leftouter Alerts on $left.AccountUpn == $right.CompromisedEntity
| extend Score = iff(RiskyCount>=1,20,0)+iff(SuspiciousProc>=1,20,0)+iff(EvidenceCount>=1,15,0)+iff(AlertCount>=1,15,0)
| where Score >= 40

Explanation:
Entity-level fusion across alerts, evidence, identity, and endpoint activity.

Tables connection:
SecurityAlert + AlertEvidence + DeviceProcessEvents + SigninLogs

Impact:
High for cross-domain prioritization.

Why needed:
Useful when multiple weak signals exist across products but no single one is decisive.

Expected noise:
Medium.

How to tune:
Restrict to critical users/devices, increase score threshold, or require multiple entity types.

Rule config:
Recommended engine: Defender Custom Detection or Sentinel
Frequency: 15 minutes
Lookback: 24 hours
Severity: Medium/High

================================================================================
33) TABLE GLOSSARY AND CONNECTION NOTES
================================================================================

Key tables used across these rules:
- SigninLogs: Entra user sign-ins, risky sign-ins, CA status, geo, IP
- AuditLogs: Entra directory audit such as roles, app consent, auth method changes
- AADServicePrincipalSignInLogs: Non-human app identity sign-ins
- AADManagedIdentitySignInLogs: Azure workload identity sign-ins
- AzureActivity: Azure control-plane operations
- OfficeActivity: Exchange, SharePoint, OneDrive, Teams unified audit
- EmailEvents: Defender for Office 365 email delivery and verdict data
- UrlClickEvents: Safe Links click activity
- MicrosoftGraphActivityLogs: Graph API usage
- CloudAppEvents: Defender for Cloud Apps SaaS and app actions
- DeviceProcessEvents: Endpoint/server process execution
- DeviceNetworkEvents: Endpoint/server outbound and inbound network activity
- DeviceRegistryEvents: Registry persistence and config changes
- DeviceFileEvents: File modifications, ransomware-style bursts, staged payloads
- DeviceEvents: Security-control related and other device events
- IdentityInfo: Account context such as blast radius or criticality
- BehaviorAnalytics: UEBA scoring and behavior anomaly context
- SecurityAlert: Provider-generated alerts
- AlertEvidence: Alert entity graph and evidence mapping

Most useful join keys:
- UserPrincipalName / AccountUpn / UserId
- AppId / ServicePrincipalId / ServicePrincipalName
- DeviceId / DeviceName
- NetworkMessageId
- CorrelationId
- IP address fields only as secondary enrichment, not primary identity keys

General tuning strategy:
1. Keep watchlists for approved apps, admin IPs, break-glass accounts, forwarding exceptions, and critical servers
2. Convert dynamic JSON parsing in AuditLogs into parser functions
3. Apply different severity models for finance, executive, admin, and standard users
4. Use device criticality or crown-jewel tagging for server-side detections
5. Prefer chain-based alerting over single-event alerting
6. Keep mail campaign compression rules separate from user-compromise rules
7. Add suppression windows where duplicate incidents are common

Final note:
These KQLs are a strong starting point for a banking-oriented Microsoft detection program,
but they are not a guarantee of complete threat coverage. Production deployment should include:
- parser normalization
- watchlists
- entity mapping
- incident grouping
- testing against real tenant data
- periodic review of thresholds and allowlists
