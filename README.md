# Phishing Email Investigation

Manual investigations of real phishing emails, written as SOC Level 1 incident reports. Each case follows the same triage workflow: read the headers, check authentication, analyze links and attachments safely, extract indicators of compromise (IOCs), map the technique to MITRE ATT&CK, and recommend a response.

No scripts or automation were used. Every finding comes from reading the raw email and checking it with public analysis tools.

## Objectives

- Triage a suspicious email and decide whether it is malicious
- Read email headers and interpret SPF, DKIM, and DMARC results
- Analyze links and domains without opening them directly
- Extract and defang IOCs (domains, URLs, IPs, sender addresses)
- Map each case to MITRE ATT&CK
- Recommend containment and detection steps
- Document findings in a clear incident report

## Investigation Workflow

| Step | What I Do |
|---|---|
| 1. Collect | Take the sample as an .eml file and open it in a text editor only, never in a mail client |
| 2. Headers | Review From, Return-Path, Reply-To, Received chain, and Authentication-Results |
| 3. Authentication | Check SPF, DKIM, and DMARC results and whether the domains align |
| 4. Content | Identify the lure, urgency, impersonation, and call to action |
| 5. Links and files | Check domains and URLs in reputation and scanning tools; never click them |
| 6. IOCs | List indicators in defanged form |
| 7. Verdict | Classify the email and rate the severity, with the evidence |
| 8. Response | Recommend containment, detection, and user actions |

## Repository Structure

```
phishing-email-investigation/
├── README.md
├── Reports/
│   └── Case_Study_01_Casino_Promo.md
├── Evidence/
│   └── Case_01/
├── Templates/
│   └── Case_Report_Template.md
```

- **Reports:** one incident report per case
- **Evidence:** screenshots and raw header extracts, in one folder per case
- **Templates:** the report template used for every case

## Case Studies

| Case | Sample | Lure | Verdict | Status |
|---|---|---|---|---|
| [Case 01](Reports/Case_Study_01_Casino_Promo.md) | Phishing Pot sample-12 | Online casino promo code | Suspicious unsolicited promotional spam (Low to Medium) | Complete |
| Case 02 | Phishing Pot sample-10007 | Ledger firmware update | To be determined | Planned |

## Tools Used

| Purpose | Tool |
|---|---|
| Header and body review | Raw .eml file in a text editor (VS Code) |
| URL scanning | urlscan.io |
| Reputation checks | VirusTotal |
| DNS lookups | Google Admin Toolbox Dig |
| Domain registration | ICANN Lookup |

## Skills Demonstrated

Phishing triage, email header analysis, SPF/DKIM/DMARC interpretation, IOC extraction, URL and domain analysis, MITRE ATT&CK mapping, incident reporting.

## Sample Source

Samples come from the public [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) collection by rf-peixoto, a database of real phishing emails collected by honeypots for research. Credit goes to the maintainers. Recipient addresses in the samples are anonymized.

## Safety Note

All analysis was done on saved .eml files and through online scanners. No link or attachment from any sample was opened directly.

## Author

Manikanta Rapolu. See also: [SOC Analyst Notes](https://github.com/Mani-pentest/soc-analyst-notes)
