# Case Study NN: <Short title, e.g. DHL shipment lure>

| Field | Detail |
|---|---|
| Sample | Phishing Pot sample number, with link |
| Date of email | Date from the Date header |
| Analyst | Manikanta Rapolu |
| Classification | Phishing / Malicious spam / Spoofing / Legitimate |
| Severity | Low / Medium / High |
| Confidence | Low / Medium / High, with one-line reason |

## Executive Summary

Two or three sentences: what the email claims to be, what it actually is, and the key evidence.

## Email Details

| Field | Value |
|---|---|
| Subject | |
| From (display name and address) | |
| Return-Path | |
| Reply-To | |
| Date | |
| Message-ID | |

## Header and Authentication Analysis

| Check | Result | What It Means |
|---|---|---|
| SPF | | Was the sending IP allowed to send for the domain? |
| DKIM | | Was the message signed, and does the signing domain match the From domain? |
| DMARC | | Did the policy apply, and what action was taken? |
| Sending infrastructure | | Where did the email really come from? |
| Mismatch checks | | Does the From domain match the sending server and the Return-Path? |

## Content Analysis

- The lure (what the email promises or threatens)
- Urgency or pressure used
- Brand or sender impersonation
- Call to action (what the user is asked to do)

## Link and Attachment Analysis

| Item | Displayed As | Real Destination (defanged) | Result |
|---|---|---|---|
| Link or file | Button or text shown | hxxps://example[.]com/path | Scanner and reputation result |

## Indicators of Compromise (IOCs)

| Type | Value (defanged) | Note |
|---|---|---|
| Domain | | |
| URL | | |
| IP address | | Mention if it belongs to a legitimate provider |
| Sender address | | |
| Subject | | |

**Note:** Do not block IPs that belong to large legitimate providers such as Google or Microsoft. Block the sender address or domain instead.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1566.002 Phishing: Spearphishing Link | |

## Risk Assessment

What could happen if a user clicked or opened the file, and who might be affected.

## Detection Opportunities

- Mail gateway or SIEM rules that would have caught this
- Authentication results worth alerting on

## Recommended Response

| Action | Detail |
|---|---|
| Contain | Block sender and domain, remove the email from mailboxes |
| Investigate | Search for other recipients and check for clicks in proxy or DNS logs |
| Remediate | Reset credentials if a user entered any, report to the abuse contact |
| Prevent | User awareness, mail filtering improvements |

## 5 Ws Summary

| Field | Answer |
|---|---|
| Time of Activity | |
| Affected Entities | |
| Reason for True Positive | |
| Reason for Escalating | |
| Remediation Actions | |
| Attack Indicators | |

## Evidence

List the screenshots stored in `Evidence/Case_NN/`, one line each, saying what each shows.

## Lessons Learned

What this case taught you and what you would check first next time.
