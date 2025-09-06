## Timeline

**Last internet-facing time:** 6 Sep 2025 10:07:32
**Machine:** `windows-target-1`
**Observation:** Device has been internet-facing for several days.

### Step 1: Confirm Internet Exposure

```kusto
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```

---

### Step 2: Check for Most Failed Logons

* Multiple threat actors discovered attempting to log into the target machine.

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

**Screenshot:** <img width="710" height="233" alt="image" src="https://github.com/user-attachments/assets/b1f11c7f-c7ae-424b-8294-ccb2fa9e3d5f" />

---

### Step 3: Validate if Top IPs Succeeded in Logons

* Took the top 3 IPs with the most logon failures and checked for any successful logons.

```kusto
let RemoteIPsInQuestion = dynamic(["147.93.150.115","47.236.231.91", "112.196.222.60"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

**Result:** No IPs have successfully logged in.

---

### Step 4: Count Failed Logon Attempts (Last 7 Days)

```kusto
DeviceLogonEvents
| where DeviceName =="windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| summarize count()
```

**Result:** 700

---

### Step 5: Count Successful Logon Attempts (Last 7 Days)

```kusto
DeviceLogonEvents
| where DeviceName =="windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| summarize count()
```

**Result:** 0

---

## Findings

* Device `windows-target-1` was confirmed internet-facing for several days.
* Multiple threat actors attempted brute-force logins using network, interactive, remote interactive, and unlock logon types.
* At least **700 failed login attempts** were recorded in the last 7 days.
* **No successful logons** were identified from the observed malicious IPs.
* No evidence of brute-force compromise was found.

---

MITRE ATT&CK TTPs

List of the relevant MITRE ATT&CK tactics and techniques observed or suspected during this scenario.

* Tactic: Initial Access → T1190 – Exploit Public-Facing Application
* Device was accidentally exposed to the internet, creating an opportunity for initial access attempts.
* Tactic: Credential Access → T1110 – Brute Force
* Multiple failed login attempts observed (700 in 7 days), consistent with brute-force activity.
* Tactic: Credential Access → T1078 – Valid Accounts
* Brute-force attempts were aimed at gaining valid account access. No successful logons detected.

---

## Next Steps / Recommendations

1. Immediately remove the device from internet exposure.
2. Review firewall rules and access controls to prevent recurrence.
3. Continue monitoring for failed login attempts from the identified IPs.
4. Consider blocking the observed IP addresses at the firewall or Defender level.
5. Audit local accounts and enforce strong password policies to mitigate brute-force risk.

---






