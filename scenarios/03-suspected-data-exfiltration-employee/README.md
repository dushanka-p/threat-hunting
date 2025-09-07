## 1. Preparation

**Goal:** Set up the hunt by defining what you’re looking for.

* An employee named **John Doe**, working in a sensitive department, recently got put on a **Performance Improvement Plan (PIP)**.
* After John threw a fit, management raised concerns that he may be planning to **steal proprietary information** and then quit the company.
* Your task: Investigate John’s activities on his corporate device (`windows-target-1`) using MDE and ensure nothing suspicious is happening.

**Activity:** Develop a hypothesis based on threat intelligence and security gaps.

* Could there be lateral movement in the network?
* John is an **administrator** on his device and not limited in which applications he uses.
* He may try to **archive/compress sensitive information** and exfiltrate it to a private drive or external location.

---

## 2. Data Collection

**Goal:** Gather relevant data from logs, network traffic, and endpoints.

**Activity:**

* Inspect **process activity** and **file system activity** for signs of compression or exfiltration.
* Ensure logs are available from these key sources for the VM:

  * `DeviceFileEvents`
  * `DeviceProcessEvents`
  * `DeviceNetworkEvents`

---

## 3. Data Analysis

**Goal:** Analyze data to test your hypothesis.

**Activity:**

1. Look for anomalies, patterns, or IOCs.
2. Check for evidence of files being **archived**.
3. If activity is found, identify exactly what is happening.
4. Take note of timestamps.
5. Search related tables for activity **±1 minute** around the same time.
6. Record findings with queries.

---

## 4. Investigation

**Goal:** Investigate suspicious findings.

**Activity:**

* Dig deeper into detected threats, determine scope, and escalate if necessary.
* Map any findings against **MITRE ATT\&CK TTPs**.
* Focus on `DeviceProcessEvents`.
* If needed, paste/upload logs into ChatGPT for further assistance.

---

## 5. Response

**Goal:** Mitigate any confirmed threats.

**Activity:**

* Work with security teams to contain, remove, and recover.
* Ask: *Can anything be done to stop or limit this?*

---

## 6. Documentation

**Goal:** Record findings and lessons learned.

**Activity:**

* Document findings, queries used, and evidence discovered.
* Use the documentation to improve future hunts.

---

## 7. Improvement

**Goal:** Refine methods for the next hunt.

**Activity:**

* Adjust strategies and tools based on what worked/didn’t.
* Ask:

  * Could we have prevented this earlier?
  * How can we improve the hunting process?

---

## Notes / Findings
