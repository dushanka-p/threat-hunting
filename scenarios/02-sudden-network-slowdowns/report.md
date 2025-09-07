# Scenario 01 – Suspicious PowerShell Port Scanning Activity

## Timeline

**Key context:**

* **Date/Time of incident:** 6 Sep 2025, starting \~13:57 UTC
* **Affected device(s):** `th--dp--win11`
* **Account involved:** `test-th.v1`
* **Initial observation:** Multiple failed outbound connections to various ports and IPs, raising suspicion of port scanning or reconnaissance.

---

### Step 1: Identify failed connections

```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by FailedConnectionsAttempts desc
```

<img width="1008" height="189" alt="image" src="https://github.com/user-attachments/assets/e9b1454c-b246-4e3a-a741-f7477b76d8b9" />


**Result:**
Device `th--dp--win11` (10.1.0.86) attempted **23 failed connections** to remote IP `10.0.0.5`.

---

### Step 2: Total failed connections from the local IP

```kusto
let IPInQuestion = "10.1.0.86";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP
| order by FailedConnectionsAttempts desc
```
<img width="742" height="218" alt="image" src="https://github.com/user-attachments/assets/2d293af2-ed5f-4b42-b675-727da4b30ed9" />

**Result / Screenshot:**
A total of **24 failed connection attempts** were made by the device.

---

### Step 3: Review all failed connections in detail

```kusto
let IPInQuestion = "10.1.0.86";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

<img width="1012" height="339" alt="image" src="https://github.com/user-attachments/assets/172dd507-c2fd-49c3-acbd-b074629eeeca" />


**Result:**
The device attempted failed connections to multiple ports (80, 110, 69, 53, 25, etc.) on `10.0.0.5`, plus one failed attempt to external IP `146.75.30.172:80`.
This pattern is consistent with **port scanning**.

---

### Step 4: Check process activity around the suspicious time

```kusto
let VMName = "windows-target-1";
let specificTime = datetime(2025-09-06T13:57:31.5180794Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

**Result:**
Multiple suspicious **powershell.exe executions** observed, including non-interactive mode with custom commands.

---

### Step 5: Expanded process review on th--dp--win11

```kusto
let VMName = "th--dp--win11";
let specificTime = datetime(2025-09-06T13:57:31.5180794Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 20m) .. (specificTime + 20m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

**Result:**
Suspicious chain detected:

* **powershell.exe** → launched `csc.exe` (C# compiler) → `cvtres.exe`.
* Indicates **on-the-fly compilation of payloads** (malware-like behavior).

---

### Step 6: Review full PowerShell command

**Result:**
PowerShell was run with `-ExecutionPolicy Bypass -NonInteractive -NoProfile`, executing a script under:

`C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\...`

This suggests **defensive evasion**, masquerading as a Defender data collection file.

---

### Step 7: Confirm direct port scan execution

```kusto
let VMName = "th--dp--win11";
let specificTime = datetime(2025-09-06T13:57:31.5180794Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 120m) .. (specificTime + 120m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
<img width="860" height="223" alt="image" src="https://github.com/user-attachments/assets/742a7134-24de-4d2a-be45-3df722d1dd19" />

**Result:**
Command line showed:

`cmd.exe /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1`

Direct evidence that the user account **test-th.v1** executed a PowerShell **port scanning script**.

---

## Findings

* Device **th--dp--win11**, under account **test-th.v1**, ran a malicious PowerShell script (`portscan.ps1`) to perform internal port scanning.
* The activity explains the multiple failed outbound connection attempts across ports and IPs.
* No malware was detected in follow-up scans, but unauthorized script execution was confirmed.
* **Risk Level:** Medium to High — indicates malicious insider activity or compromised user account.

---

## MITRE ATT\&CK TTPs

* **Tactic: Discovery** → **Technique: T1046 – Network Service Scanning**
* **Tactic: Execution** → **Technique: T1059.001 – PowerShell**
* **Tactic: Defense Evasion** → **Technique: T1055 – Execution with Bypass (ExecutionPolicy Bypass)**

---

## Next Steps / Recommendations

1. **Quarantine the device** (`th--dp--win11`) — completed.
2. **Conduct malware scan** — completed, no threats found.
3. **Submit ticket for reimaging/rebuilding the device** — completed.
4. **Reset account credentials for test-th.v1** to prevent persistence.
5. **Hunt across environment** for other occurrences of `ExecutionPolicy Bypass` and `portscan.ps1`.
6. **Implement controls**:

   * Block execution from `C:\programdata\`.
   * Enforce Defender ASR rules / AppLocker to restrict PowerShell misuse.
   * Increase monitoring for suspicious process chains (e.g., PowerShell → csc.exe → cvtres.exe).

---

