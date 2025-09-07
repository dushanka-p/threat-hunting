## Summary

* **Date/Time:** 7 Sep 2025 – 09:47 UTC
* **Device:** `th--dp--win11`
* **Initial Observation:** ZIP file created, renamed, and moved to a backup location.

## Key Findings

* PowerShell script executed during the same timeframe.
* 7-Zip was silently installed and used to compress employee data.
* Archiving behavior matches **data staging** tactics.
* No suspicious outbound network activity detected (no confirmed exfiltration).

## MITRE ATT\&CK TTPs

* **T1059.001 – PowerShell Execution** → Used to install & run 7-Zip.
* **T1560.001 – Archive Collected Data** → 7-Zip compressed employee files.
* **T1070.004 – Indicator Removal (File Deletion/Archiving)** → Files moved/renamed to obscure activity.

## Risk Level

**Medium–High** → Insider threat suspected, staging data for potential future exfiltration.

## Recommended Actions

1. Keep system isolated.
2. Conduct forensic review (disk + memory).
3. Escalate to HR/management for insider threat assessment.
4. Implement detection rules for ZIP creation + PowerShell execution.

---
