# Custom Detection Rule Fidelity (Microsoft Defender XDR)

A KQL query that measures the fidelity of each **Microsoft Defender XDR custom detection rule** by breaking down the alerts it raised into **True Positives**, **False Positives**, and **Benign Positives** over the last 30 days, along with the reasons analysts gave for each verdict.

Use it to find which of your custom detection rules are noisy, which are low-fidelity, and which need tuning, exclusions, or retirement.

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

---

## Overview

When analysts close an incident, they assign it a classification and a reason. This query traces each alert raised by a custom detection rule back to the incident it belongs to, applies that incident's classification to the alert, and summarizes the results per rule:

| Metric | What it tells you |
|---|---|
| **True Positive (TP)** | The rule fired on real malicious or unwanted activity. |
| **False Positive (FP)** | The rule fired, but its logic was wrong; nothing suspicious actually happened. |
| **Benign Positive (BP)** | The rule's logic was correct and the activity really happened, but it was expected or authorized (e.g. a pentest, an admin task, a known tool). |

Each row of the result is one rule, with these columns:

| Column | Meaning |
|---|---|
| `RuleName` | The custom detection rule (taken from the alert title). |
| `TotalAlerts` | Every alert the rule raised in the lookback period, classified or not. |
| `TruePositive` / `FalsePositive` / `BenignPositive` | Number of the rule's alerts that belonged to incidents closed with that classification. |
| `TruePositivePercent` / `FalsePositivePercent` / `BenignPositivePercent` | Share of the rule's **classified** alerts with each classification. |
| `ReasonBreakdown` | Count of alerts for each classification and reason pair, e.g. `{"FalsePositive: IncorrectAlertLogic": 4}`. |

---

## Requirements

- The **unified Microsoft Defender portal** with a **Microsoft Sentinel** workspace connected, so `AlertInfo` and the Sentinel tables can be queried together in Advanced Hunting
- Defender XDR alerts and incidents flowing into Sentinel (populating **`SecurityAlert`** and **`SecurityIncident`**)
- Read access to **`AlertInfo`**, **`SecurityAlert`**, and **`SecurityIncident`**
- Analysts who **classify incidents on closure**, including a classification reason. Only incidents closed as TP, FP, or BP contribute to the percentages, so accuracy depends on consistent closure hygiene.

---

## The Query

```kusto
let lookbackPeriod = 30d;
// find every alert raised by a custom detection rule.
let CustomDetectionAlerts = AlertInfo
    | where Timestamp > ago(lookbackPeriod)
    // the DetectionSource for Defender XDR custom detection rules is "Custom detection"
    | where DetectionSource == "Custom detection"
    | project AlertId, RuleName = Title
    | distinct AlertId, RuleName;
// map Defender alert IDs to the IDs referenced by Sentinel incidents
// verify that VendorOriginalId matches AlertInfo.AlertId in your environment
let AlertIdLookup = SecurityAlert
    | where TimeGenerated > ago(lookbackPeriod)
    | project DefenderAlertId = VendorOriginalId, SentinelAlertId = SystemAlertId
    | distinct DefenderAlertId, SentinelAlertId;
// get closed incidents that have a verdict.
// each incident is logged many times as it changes, so keep only its latest version,
// then split it into one row per alert it contains
let ClassifiedIncidents = SecurityIncident
    | where TimeGenerated > ago(lookbackPeriod)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Status == "Closed"
    | where Classification in ("TruePositive", "FalsePositive", "BenignPositive")
    | mv-expand SentinelAlertId = AlertIds to typeof(string)
    | project SentinelAlertId, Classification, ClassificationReason;
// attach each incident's verdict to the custom detection alerts
// alerts with no verdict yet keep an empty Classification
let AlertsWithVerdicts = CustomDetectionAlerts
    | join kind=leftouter AlertIdLookup on $left.AlertId == $right.DefenderAlertId
    | join kind=leftouter ClassifiedIncidents on SentinelAlertId
    | project AlertId, RuleName, Classification, ClassificationReason;
// count the reasons analysts gave for each verdict, per rule
// example output -> {"FalsePositive: IncorrectAlertLogic": 4, "TruePositive: SuspiciousActivity": 2}
let ReasonBreakdownByRule = AlertsWithVerdicts
    | where isnotempty(Classification)
    | extend Reason = iff(isempty(ClassificationReason), "NoReasonGiven", ClassificationReason)
    | summarize AlertCount = dcount(AlertId) by RuleName, Verdict = strcat(Classification, ": ", Reason)
    | summarize ReasonBreakdown = make_bag(bag_pack(Verdict, AlertCount)) by RuleName;
// count verdicts per rule and turn them into percentages.
AlertsWithVerdicts
| summarize
    TotalAlerts    = dcount(AlertId),
    TruePositive   = dcountif(AlertId, Classification == "TruePositive"),
    FalsePositive  = dcountif(AlertId, Classification == "FalsePositive"),
    BenignPositive = dcountif(AlertId, Classification == "BenignPositive")
    by RuleName
| extend AlertsWithVerdict = TruePositive + FalsePositive + BenignPositive
| extend
    TruePositivePercent   = round(100.0 * TruePositive   / AlertsWithVerdict, 1),
    FalsePositivePercent  = round(100.0 * FalsePositive  / AlertsWithVerdict, 1),
    BenignPositivePercent = round(100.0 * BenignPositive / AlertsWithVerdict, 1)
| join kind=leftouter ReasonBreakdownByRule on RuleName
| project RuleName, TotalAlerts,
          TruePositive, FalsePositive, BenignPositive,
          TruePositivePercent, FalsePositivePercent, BenignPositivePercent,
          ReasonBreakdown
| order by TotalAlerts desc
```

See [`alert_fidelity.kql`](alert_fidelity.kql) for the full version with header comments.

---

## How It Works

Microsoft keeps the data this query needs in three separate tables, so the query links them together:

| Table | What it provides |
|---|---|
| `AlertInfo` | Which alerts came from custom detection rules (`DetectionSource == "Custom detection"`), identified by the Defender `AlertId`. |
| `SecurityIncident` | The incident's `Classification` and `ClassificationReason`, plus the list of alerts it contains (`AlertIds`, which holds Sentinel alert IDs). |
| `SecurityAlert` | The bridge between the two: each row holds both the Sentinel ID (`SystemAlertId`) and the original Defender ID (`VendorOriginalId`). |

The path is: `AlertInfo.AlertId` → `SecurityAlert.VendorOriginalId` / `SecurityAlert.SystemAlertId` → `SecurityIncident.AlertIds`.

1. **Find custom detection alerts.** Pulls every alert from `AlertInfo` in the last 30 days whose source is `Custom detection`, keeping the alert ID and the rule name.
2. **Build an ID lookup.** Pulls each pair of Defender and Sentinel alert IDs from `SecurityAlert`.
3. **Collect classified incidents.** The `SecurityIncident` table logs a new row every time an incident is updated, so `arg_max(TimeGenerated, *)` keeps only the latest record per incident. The query then keeps incidents that are closed and classified as TP, FP, or BP, and splits each incident into one row per alert it contains.
4. **Attach verdicts to alerts.** Joins the custom detection alerts to the ID lookup, then to the classified incidents. Left outer joins keep alerts that have no verdict yet, so they still count toward `TotalAlerts`.
5. **Tally the reasons.** For each rule, counts how many alerts received each classification and reason pair, and packs the counts into a single `ReasonBreakdown` column. Incidents closed without a reason are labeled `NoReasonGiven`.
6. **Summarize per rule.** Counts total alerts and alerts per classification, calculates percentages of the classified alerts (rounded to one decimal place), adds the reason breakdown, and sorts the rules by alert volume.

---

## Sample Output

| RuleName | TotalAlerts | TruePositive | FalsePositive | BenignPositive | TruePositivePercent | FalsePositivePercent | BenignPositivePercent | ReasonBreakdown |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Suspicious LSASS Access | 40 | 10 | 25 | 5 | 25.0 | 62.5 | 12.5 | `{"TruePositive: SuspiciousActivity": 10, "FalsePositive: IncorrectAlertLogic": 25, "BenignPositive: SuspiciousButExpected": 5}` |
| Encoded PowerShell from Office | 18 | 6 | 0 | 12 | 33.3 | 0.0 | 66.7 | `{"TruePositive: SuspiciousActivity": 6, "BenignPositive: SuspiciousButExpected": 12}` |
| New Service Installed via PsExec | 7 | 0 | 0 | 0 | | | | |

*Rule names and numbers are illustrative only.*

---

## Interpreting the Results

- **High `TotalAlerts`** points to noisy rules, regardless of classification. Start tuning work at the top of the list.
- **High `FalsePositivePercent`** suggests the rule's logic is too broad or relies on fragile indicators. Look for `IncorrectAlertLogic` or `InaccurateData` in `ReasonBreakdown`. These rules usually need logic changes, not just exclusions.
- **High `BenignPositivePercent`** suggests the logic is sound but the environment has a lot of expected activity that matches it. Look for `SuspiciousButExpected` in `ReasonBreakdown`. These rules usually benefit from narrow, well-documented exclusions (specific accounts, hosts, signers, or paths).
- **A large gap between `TotalAlerts` and the classified counts** means many of the rule's alerts are in open incidents, incidents closed as `Undetermined` or without a classification, or incidents the query couldn't match. Address this before trusting the percentages.
- **Blank percentage columns** mean none of the rule's alerts have a verdict yet.

Always read the percentages alongside `TotalAlerts`. A rule with 50 alerts and only 2 classified could show 100% true positive.

---

## Customization

**Change the lookback window**

```kusto
let lookbackPeriod = 14d;
```

`AlertInfo` retains 30 days of data in Advanced Hunting, so values above `30d` won't return older custom detection alerts.

**See individual alerts instead of per-rule totals** by replacing everything after the `ReasonBreakdownByRule` definition with:

```kusto
AlertsWithVerdicts
| order by RuleName asc
```

**Count incidents (analyst decisions) instead of alerts** by adding `IncidentNumber` to the `project` lines in `ClassifiedIncidents` and `AlertsWithVerdicts`, then counting it in the final `summarize`:

```kusto
    TruePositive   = dcountif(IncidentNumber, Classification == "TruePositive"),
    FalsePositive  = dcountif(IncidentNumber, Classification == "FalsePositive"),
    BenignPositive = dcountif(IncidentNumber, Classification == "BenignPositive")
```

**Group rules that use dynamic alert titles** by normalizing the title in `CustomDetectionAlerts`, for example by stripping everything after a separator:

```kusto
    | project AlertId, RuleName = trim_end(@"\s*[-:].*", Title)
```

---

## Limitations

- **Garbage in, garbage out.** Results are only as accurate as your analysts' closure classifications and reasons.
- **Incident-level, not alert-level.** Classifications are read from the incident, and every alert in the incident inherits that classification. Alert-level classifications set in the Defender portal are not used. If you need them, the Microsoft Graph security API (`/security/alerts_v2`) exposes them per alert.
- **One decision can count many times.** If an incident holds several alerts from the same rule, one analyst classification is counted once per alert.
- **Mixed incidents.** An incident can contain alerts from built-in detections or other rules. Your rule's alerts inherit the incident's classification even if the analyst's decision was really about a different alert.
- **Percentages only reflect classified alerts.** Open incidents, `Undetermined` incidents, and incidents closed without a classification are excluded from the percentages but included in `TotalAlerts`.
- **30-day limit.** `AlertInfo` only retains 30 days of data in Advanced Hunting, which caps the lookback window.
- **ID mapping assumption.** The query assumes `SecurityAlert.VendorOriginalId` matches `AlertInfo.AlertId`. Verify this in your environment; unmatched alerts count toward `TotalAlerts` but never receive a classification.
- **Dynamic alert titles** split one rule into several rows, since `RuleName` comes from the alert title. See [Customization](#customization) for a workaround.
