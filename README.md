# 🚨 **Potential Lateral Movement via RDP Detected**

**Author:** Emmanuel Olawuyi 
**Date:** Jan 11, Updated: Jan 12  
**Reading Time:** 8 min

---

## 📌 **High-Level Overview**
Detect and investigate **potential lateral movement** within your network, specifically focusing on suspicious RDP activity. 

**Quick Deploy:** Copy and use the provided KQL query in your Microsoft Sentinel workspace.

---

## 📝 **Description**
This query identifies **potential lateral movement** within a network by analyzing RDP connections (`EventID 4624`, `LogonTypes 3, 7, and 10`). It detects cases where:
- An RDP connection is made to an initial system.
- A subsequent RDP connection is established from the initial compromised system to a second system using the same account within a 30-minute window.

The focus is on **logon type 10** (Interactive Remote) to highlight unusual RDP behavior often associated with lateral movement tactics used by attackers.

---

### 🔍 **Framework**

**MITRE ATT&CK™**
- **Tactic:** Lateral Movement ([TA0008](https://attack.mitre.org/tactics/TA0008/))
- **Technique:** Remote Services ([T1021](https://attack.mitre.org/techniques/T1021/))

---

## 📊 **Rule Details**
- **Type:** KQL  
- **Rule ID:** `de3fffa4-2bc6-47fb-948c-9a9b1acb727d`  
- **Severity:** Medium/High  
- **Frequency:** Runs every 1 day  
- **Alert per Event:** Yes  
- **Domain:** Endpoint  
- **OS:** Windows  
- **Event ID:** 4625  
- **Use Case:** Threat Detection  
- **Version:** 1.1  
- **Author:** Aniket

---

## 🔑 **Pre-Requisites**
1. Data collection via Azure Monitor Agent using a data collection rule in Microsoft Sentinel.  
2. Windows Security Events via AMA data connector.  
3. Microsoft Sentinel Workspace with sufficient RBAC permissions.

---

## 🛠️ **Investigation Guide**

### **Triage and Analysis**
This rule identifies suspicious lateral movement via RDP connections. 

**Noise Reduction Tips:**
- Group alerts.
- Add whitelisted entities to a watchlist.
- Remove logon types 3 and 7.

### **Possible Investigation Steps**
1. Investigate login failure usernames.
2. Check the source IP address of failed SSH login attempts.
3. Run a threat intelligence check for the IP address.
4. Review related alerts for the user/host in the last 48 hours.
5. Identify the source and target computers and their roles in the environment.
6. Analyze false positives and create exemptions if needed.

---

### **Related Rules**
- **RDP Nesting:** `69a45b05-71f5-45ca-8944-2e038747fb39`

---

## 🚑 **Response and Remediation**
1. Initiate the incident response process.
2. Isolate the involved hosts.
3. Add the attacker’s IP to Threat Intelligence and consider blocking it.
4. Investigate credential exposure and reset compromised credentials.
5. Identify and mitigate the initial attack vector to prevent reinfection.

---

## 📜 **Query**

```kql
// Suspicious Lateral Movement across Two Servers via RDP
let endtime = 1d;
let rdpConnection1 =
  SecurityEvent
  | where TimeGenerated >= ago(endtime)
  | where EventID == 4624 and LogonType in (7, 3, 10)
  | extend
      FirstHop = bin(TimeGenerated, 1m),
      FirstComputer = toupper(Computer),
      FirstRemoteIPAddress = IpAddress,
      FirstComputerDomain = tostring(split(Account, @"\\")[0]),
      Account = tolower(Account);
let rdpConnection2 =
  SecurityEvent
  | where TimeGenerated >= ago(endtime)
  | where EventID == 4624 and LogonType in (7, 3, 10)
  | extend
      SecondHop = bin(TimeGenerated, 1m),
      SecondComputer = toupper(Computer),
      SecondRemoteIPAddress = IpAddress,
      SecondComputerDomain = tostring(split(Account, @"\\")[0]),
      Account = tolower(Account);
SecurityEvent
| where TimeGenerated >= ago(endtime)
| where EventID == 4624 and LogonType in (7, 3, 10)
| join kind=innerunique rdpConnection1 on TargetUserName
| join kind=innerunique rdpConnection2 on TargetUserName
| where FirstComputer != SecondComputer
| where FirstRemoteIPAddress != SecondRemoteIPAddress
| where SecondHop > FirstHop
| where SecondHop <= FirstHop + 30m
| summarize
    FirstHopFirstSeen = min(FirstHop),
    FirstHopLastSeen = max(FirstHop)
  by
    TargetUserName,
    FirstHop,
    FirstComputer,
    FirstRemoteIPAddress,
    FirstComputerDomain,
    SecondHop,
    SecondComputer,
    SecondRemoteIPAddress,
    SecondComputerDomain,
    AccountType,
    Activity,
    LogonTypeName
| where LogonTypeName =~ '10 - RemoteInteractive'
| distinct
    TargetUserName,
    FirstHop,
    FirstComputer,
    FirstRemoteIPAddress,
    FirstComputerDomain,
    SecondHop,
    SecondComputer,
    SecondRemoteIPAddress,
    SecondComputerDomain,
    AccountType,
    Activity,
    LogonTypeName
```

---

## 📚 **References**
- [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [MITRE ATT&CK - Remote Services](https://attack.mitre.org/techniques/T1021/)
