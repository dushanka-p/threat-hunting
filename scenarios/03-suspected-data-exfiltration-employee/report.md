## Timeline

**Key context:**

* **Date/Time of incident:** 7 Sep 2025 09:47 UTC
* **Affected device(s):** `th--dp--win11`
* **Initial observation:** A ZIP file was created and then moved/renamed shortly after.

---

### Step 1: Initial Check – File Events

```kusto
DeviceFileEvents
| where DeviceName == "th--dp--win11"
| where FileName endswith ".zip"
| order by Timestamp desc
```

**Result:**

* File created: **7 Sep 2025 10:47:00**
* Immediately renamed and moved to backup location.

**Screenshot:** <img width="1417" height="362" alt="image" src="https://github.com/user-attachments/assets/85ee4e78-7be1-40c3-895c-d78539d3d4da" />

---

### Step 2: Follow-up Investigation – Process Events Around ZIP Creation

I correlated the timestamp of the ZIP creation with process activity ±2 minutes.

```kusto
// 2025-09-07T09:47:00.359506Z
let VMName = "th--dp--win11";
let specificTime = datetime(2025-09-07T09:47:00.359506Z);

DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

**Result / Screenshot:** <img width="1636" height="578" alt="image" src="https://github.com/user-attachments/assets/f0893f64-ebba-4497-9ef2-76099f441cda" />

**Findings:**

* PowerShell was executed during this time.
* A script silently installed **7-Zip**.
* 7-Zip was used to compress employee data into an archive.

---

### Step 3: Additional Validation – Network Events

Checked for signs of exfiltration within ±4 minutes of the archive creation.

```kusto
// 2025-09-07T09:47:00.359506Z
let VMName = "th--dp--win11";
let specificTime = datetime(2025-09-07T09:47:00.359506Z);

DeviceNetworkEvents
| where Timestamp between ((specificTime - 4m) .. (specificTime + 4m))
| where DeviceName == VMName
| order by Timestamp desc
```

**Result:**

* No suspicious outbound connections detected.
* No evidence of exfiltration at this stage.

---

## Findings

* **What happened?**
  A ZIP file was created, renamed, and moved. Investigation revealed that a PowerShell script installed 7-Zip and used it to compress employee data into an archive.

* **What did the queries confirm or deny?**

  * Confirmed: Suspicious archiving activity using 7-Zip.
  * Denied: No network-based data exfiltration detected during this timeframe.

* **Did any attacks succeed?**

  * Data staging via archiving **appears successful**.
  * Data exfiltration attempt was **not observed**.

* **Risk level / likelihood of compromise:**
  **Medium-High** — archiving of sensitive files could indicate insider threat activity, staging data for later theft.

---

## MITRE ATT\&CK TTPs

* **Tactic:** Execution → **Technique:** T1059.001 – Command and Scripting Interpreter: PowerShell

  * PowerShell was used to install and execute 7-Zip.

* **Tactic:** Collection → **Technique:** T1560.001 – Archive Collected Data: Archive via Utility

  * 7-Zip was used to compress employee data into an archive.

* **Tactic:** Defense Evasion → **Technique:** T1070.004 – Indicator Removal on Host: File Deletion

  * Archiving and moving files may indicate an attempt to obscure staging or evade detection.

---

## Next Steps / Recommendations

1. **Immediate containment** – Keep the system isolated to prevent potential data exfiltration.
2. **Forensic review** – Capture disk and memory images for further investigation.
3. **Insider risk assessment** – Engage HR and management to review employee behavior, given the context of potential insider threat.
4. **Monitoring** – Increase watch on similar PowerShell and 7-Zip activity across the environment.
5. **Detection rule** – Implement Sentinel/MDE detection for ZIP creation combined with PowerShell execution.

---
