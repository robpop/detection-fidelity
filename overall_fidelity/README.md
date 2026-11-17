# Detection Fidelity Metrics (Microsoft Sentinel)

A KQL query that measures the overall fidelity of your detections by breaking down closed Microsoft Sentinel incidents into **True Positives**, **False Positives**, and **Benign Positives** over the last 90 days.

Use it to track how much of your SOC's triage effort goes to real threats versus noise, to report detection quality to leadership, and to spot when your detection library needs tuning.

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [The Query](#the-query)
- [How It Works](#how-it-works)
- [Sample Output](#sample-output)
- [Interpreting the Results](#interpreting-the-results)
- [Customization](#customization)
- [Limitations](#limitations)
- [License](#license)

---

## Overview

Every incident an analyst closes in Microsoft Sentinel is assigned a classification. This query takes those classifications and turns them into a single fidelity snapshot:

| Metric | What it tells you |
|---|---|
| **True Positive (TP)** | The detection fired on real malicious or unwanted activity. |
| **False Positive (FP)** | The detection fired, but its logic was wrong; nothing suspicious actually happened. |
| **Benign Positive (BP)** | The detection logic was correct and the activity really happened, but it was expected or authorized (e.g. a pentest, an admin task, a known tool). |

A high TP percentage means analysts spend their time on real threats. A high FP or BP percentage points to detections that need tuning, exclusions, or retirement.

---

## Requirements

- A **Microsoft Sentinel** workspace (or the unified Microsoft Defender portal with Sentinel connected)
- Read access to the **`SecurityIncident`** table
- Analysts who **classify incidents on closure**. The query only counts incidents that have a TP, FP, or BP classification, so its accuracy depends on consistent closure hygiene.

---

## The Query

```kusto
SecurityIncident
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentName
| where CreatedTime >= ago(90d)
| where Status == "Closed"
| where Classification in ("TruePositive", "FalsePositive", "BenignPositive")
| summarize
    TruePositives = countif(Classification == "TruePositive"),
    FalsePositives = countif(Classification == "FalsePositive"),
    BenignPositives = countif(Classification == "BenignPositive")
| extend Total = TruePositives + FalsePositives + BenignPositives
| extend
    TruePositivePct = round(100.0 * TruePositives / Total, 2),
    FalsePositivePct = round(100.0 * FalsePositives / Total, 2),
    BenignPositivePct = round(100.0 * BenignPositives / Total, 2)
| project Total, TruePositives, TruePositivePct,
          FalsePositives, FalsePositivePct,
          BenignPositives, BenignPositivePct
```

---

## How It Works

1. **Deduplicate incidents.** The `SecurityIncident` table logs a new row every time an incident is updated (status change, owner change, comment, etc.). `arg_max(TimeGenerated, *)` keeps only the most recent record per incident, so each incident is counted once using its latest state. Grouping by `TenantId` as well as `IncidentName` keeps incidents distinct across workspaces in multi-tenant setups.
2. **Scope to the last 90 days.** Filters on `CreatedTime`, so the window is based on when the incident was created rather than when it was last modified.
3. **Keep only closed, classified incidents.** Open incidents and incidents classified as `Undetermined` are excluded, since they don't say anything definitive about detection quality.
4. **Count each classification** with `countif()`.
5. **Calculate percentages** of the total, rounded to two decimal places.
6. **Project** a clean, single-row result.

---

## Sample Output

| Total | TruePositives | TruePositivePct | FalsePositives | FalsePositivePct | BenignPositives | BenignPositivePct |
|---:|---:|---:|---:|---:|---:|---:|
| 1,240 | 372 | 30.00 | 248 | 20.00 | 620 | 50.00 |

*Numbers are illustrative only.*

---

## Interpreting the Results

- **Rising TP%** over time is a good sign your tuning work is paying off.
- **High FP%** suggests detection logic is too broad or relies on fragile indicators. These rules usually need logic changes, not just exclusions.
- **High BP%** suggests the logic is sound but the environment has a lot of expected activity that matches it. These rules usually benefit from narrow, well-documented exclusions (specific accounts, hosts, signers, or paths).
- **Low `Total`** relative to the number of incidents you actually closed means many incidents are being closed as `Undetermined` or without a classification, which is worth addressing before trusting the percentages.

There's no universal "good" number. Fidelity targets depend on your environment, your detection philosophy (broad hunting-style rules vs. high-confidence alerts), and your team's capacity. Use the trend over time as your main signal.

---

## Customization

**Change the lookback window**

```kusto
| where CreatedTime >= ago(30d)
```

**Break down by tenant** (MSSP / multi-workspace) by adding `by TenantId` to the first `summarize` after the classification filter.

**Track the trend over time** by adding `by bin(CreatedTime, 7d)` (weekly) or `by startofmonth(CreatedTime)` (monthly) to the counting `summarize`, then charting the result with `| render timechart`.

---

## Limitations

- **Garbage in, garbage out.** Results are only as accurate as your analysts' closure classifications.
- **Incident-level, not alert-level.** An incident can contain multiple alerts from multiple rules, so a single classification applies to all of them.
- **Undetermined incidents are excluded** from the totals and percentages.
- **Empty results.** If no incidents match in the window, `Total` is `0` and the percentage columns return no meaningful value.
