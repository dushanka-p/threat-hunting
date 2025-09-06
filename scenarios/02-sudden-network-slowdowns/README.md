# Scenario 2 – Sudden Network Slowdowns

* **Run the following PowerShell command on your VM after onboarding it to MDE:**

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1' -OutFile 'C:\programdata\portscan.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
```

---

## 1. Preparation

* **Goal:** Set up the hunt by defining what you're looking for.
* **Context:**

  * The server team has noticed **significant network performance degradation** on older devices in the `10.0.0.0/16` network.
  * External DDoS attacks have been ruled out. The security team suspects internal activity.
* **Hypothesis:** Could there be **lateral movement** in the network?
* **Environment:**

  * All traffic originating from the local network is **allowed by default**.
  * **Unrestricted use of PowerShell and other applications** exists.
  * It’s possible someone is downloading large files or conducting **port scans**.

---

## 2. Data Collection

* **Goal:** Gather relevant data from logs, network traffic, and endpoints.
* **Activity:**

  * Inspect logs for **excessive successful/failed connections**.
  * If suspicious devices are found, pivot and inspect file/process events.
* **Key sources to check:**

  * `DeviceNetworkEvents`
  * `DeviceFileEvents`
  * `DeviceProcessEvents`

---

## 3. Data Analysis

* **Goal:** Analyze data to test the hypothesis.
* **Activity:**

  * Look for anomalies, patterns, or IOCs (Indicators of Compromise).
  * Specifically: **Excessive network connections** to/from hosts.
  * Record: **queries, logs, timestamps** for reference.

---

## 4. Investigation

* **Goal:** Investigate suspicious findings.
* **Activity:**

  * Dig deeper into detected threats, determine scope, and escalate if needed.
  * Cross-reference findings with **MITRE ATT\&CK TTPs**.
  * Search `DeviceFileEvents` and `DeviceProcessEvents` around the same time as findings in `DeviceNetworkEvents`.
  * This helps confirm the root cause of slowdowns.
* **Tip:** You can use ChatGPT by pasting/uploading logs for additional analysis.

---

## 5. Response

* **Goal:** Mitigate confirmed threats.
* **Activity:** Work with security teams to contain, remove, and recover.
* **Question to ask:** *Can anything be done right now to reduce impact?*

---

## 6. Documentation

* **Goal:** Record findings and learn from them.
* **Activity:** Document:

  * What you found.
  * Queries used.
  * Timestamps and events.
  * Lessons learned.

---

## 7. Improvement

* **Goal:** Strengthen security posture for future hunts.
* **Activity:**

  * Identify prevention methods (e.g., restricting PowerShell).
  * Improve hunting playbooks and processes.
  * Ask: *Could this have been prevented?* *How do we improve next time?*

---

## Notes / Findings

### Sample Queries (spoilers, highlight/copy to reveal)

**1. Count failed connections (IPs with excessive attempts):**

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by FailedConnectionsAttempts desc
```

**2. Observe total failed connections for a specific IP:**

```kql
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP
| order by FailedConnectionsAttempts desc
```

**3. List all failed connections for the IP in question:**

```kql
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

**4. Observe process activity around the suspicious time window:**

```kql
let VMName = "windows-target-1";
let specificTime = datetime(2024-10-18T04:09:37.5180794Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

---

## Timeline Summary and Findings

*(Fill in after investigation with timestamps, key events, and confirmed findings.)*

---
