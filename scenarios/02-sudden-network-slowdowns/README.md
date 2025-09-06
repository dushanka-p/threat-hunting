# Scenario 2 – Sudden Network Slowdowns

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
