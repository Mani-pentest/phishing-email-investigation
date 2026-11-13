# Case Study 03: Fake Microsoft Terms Update Email Asking for Billing Sign-In

| Field | Detail |
|---|---|
| Sample | [Phishing Pot sample-10026](https://github.com/rf-peixoto/phishing_pot) |
| Date of email | 30 March 2026 |
| Analyst | Manikanta Rapolu |
| Classification | Phishing: Microsoft-impersonating lure to harvest sign-in and payment details |
| Severity | High potential impact. No evidence in this sample that any recipient clicked or entered details |
| Confidence | High for the classification. The landing page, the sender account's status, and the purpose of the attachments could not be confirmed |

## Executive Summary

The email, titled "Terms Update", claims that service terms have changed and tells the recipient to sign in and review the billing information and saved payment method. The sender's display name imitates "Microsoft Mail Support" using a look-alike letter and invisible characters, and the Microsoft logo is drawn with coloured table cells instead of an image. SPF, DKIM, and DMARC all pass, because the message was sent through an authenticated Gmail SMTP session for the domain `brighthomedaycare.com`. The first hop, however, is a Windows host on Amazon EC2 rather than a small business, which points to an attacker using a valid account. The only link goes to a `v2` subdomain of that same domain, which two VirusTotal vendors flag, and the page could not be loaded. Three Apple configuration-profile attachments are also included. They look harmless, appear in other Phishing Pot samples, and their purpose is not determined.

## Email Details

| Field | Value |
|---|---|
| Subject | Terms Update Effective Mon, March 30, 2026 |
| From | Display name imitating "Microsoft Mail Support", address `co@brighthomedaycare[.]com` |
| Return-Path | `co@brighthomedaycare[.]com` |
| To | `customer@postmaster[.]microsoft365[.]com` (a decoy address; real recipients are not shown) |
| Reply-To | Not present |
| Date | Mon, 30 Mar 2026 17:45:19 +0000 |
| Message-ID | `<5097921302428.940058623303060.5978867312.979107518860@csp-obgw-0005a.ser.ppops.net>` |
| X-Mailer | `Gmail Default Mailer`s - **<random string>**` |
| Format | HTML and plain-text parts, plus 3 attachments |

## Sender Display Name Analysis

The From display name is MIME-encoded. Decoding the first encoded word in CyberChef (From Base64, then To Hex) shows:

| Bytes | Meaning |
|---|---|
| `e1 8e b7` | Cherokee letter MU (U+13B7), which looks like a capital "M" |
| `f3 a0 84 b9` (repeated) | Invisible Variation Selector characters (U+E0139) inserted between letters |
| `69 63 72 6f 73 6f` | The plain ASCII letters "icroso" |

The name therefore reads as "Microsoft Mail Supports" to a person but does not match a simple text search for the word "Microsoft". This is deliberate filter and reader evasion.

## Header and Authentication Analysis

| Check | Result | What It Means |
|---|---|---|
| SPF | Pass for `brighthomedaycare.com`, sending IP 209.85.128.68 | The Google server that relayed the message is authorised for the domain |
| DKIM | Pass, signed by `brighthomedaycare.com` | The message was signed with the domain's own key |
| DMARC | `bestguesspass` | Microsoft's result when the domain publishes no DMARC policy and the authentication aligns |
| Composite authentication | Pass | Microsoft's combined check also passed |

**Note:** Every authentication check passes here, and the email is still phishing. Authentication proves that the domain's own mail infrastructure sent the message. It does not prove that the person using it is trustworthy.

### Message origin and routing

| Hop (oldest first) | Detail |
|---|---|
| 1 | `EC2AMAZ-A9QNUAT` at `2a05:d01c:f37:6300:569f:d15f:9569:3e0b` connects to `smtp.gmail.com` with authenticated ESMTPS at 17:45:19 UTC |
| 2 | Google relays the message from `mail-wm1-f68.google.com` (209.85.128.68) at 17:45:21 UTC |
| 3 | Microsoft front-end servers accept it |
| 4 | Final delivery hop at 17:45:24 UTC |

VirusTotal places the origin address in Amazon's network (AS 16509, Ireland) with 0 of 92 vendors flagging it. `EC2AMAZ-` is the default hostname pattern of a Windows server on Amazon EC2.

### Additional header observations

- The hostname `EC2AMAZ-A9QNUAT` and an authenticated Gmail SMTP session do not fit a small daycare business sending a legitimate notice. They fit a bulk sender logged in to the account.
- The X-Mailer value is a custom string that Gmail does not normally add, and the Message-ID comes from an unrelated mail system rather than Gmail. Both fit a bulk-mailing tool.
- The To address is a decoy, which suggests recipients were placed in Bcc.
- This does not prove that the account was compromised. It is the most likely explanation, but it is an inference.

## Content Analysis

### The lure

"Important Update to Service Terms": the terms changed, the account is "still fully active", and nothing changes in the services.

### Urgency or pressure used

The recipient is told to act "to ensure your services continue without any problems in the coming period". The pressure is soft rather than a hard deadline.

### Brand or sender impersonation

The display name imitates Microsoft, and the Microsoft four-colour logo is built from coloured table cells, so it appears even when images are blocked. The body never names a product, and the signature is a generic "Account Services Team". The recipient is "Hello" with no name.

### Call to action

The button text is "Sign In & Review Payment Information". The payment method saved on file is mentioned specifically, which signals the goal of collecting credentials and card details.

## Link Analysis

The email contains one link:

| Displayed As | Real Destination (defanged) |
|---|---|
| Sign In & Review Payment Information | `hxxps://www[.]v2[.]brighthomedaycare[.]com/` |

The destination is not a Microsoft domain. It is a `v2` subdomain of the sender's own domain, which is a typical place for a phishing page on a compromised or abused website.

### VirusTotal findings for the URL

| Vendor | Label |
|---|---|
| Fortinet | Phishing |
| Webroot | Malicious |

Two of 93 vendors flag the URL. Webroot categorises it as "Phishing and Other Frauds", while BitDefender categorises it as "parked" and Forcepoint as "human interests". The URL had never been submitted before; the first submission was on 11 November 2026, so there is no earlier history. VirusTotal recorded no HTTP status.

### VirusTotal findings for the domain

Two of 92 vendors flag `www.v2.brighthomedaycare.com` (the same two). The registrar is GoDaddy, and the domain is about 18 years old.

### urlscan investigation

urlscan.io was run twice: a public scan from Switzerland and an unlisted scan from the United States. Both returned "We could not scan this website" with no screenshot, which means the site could not be contacted or loaded. The page content therefore could not be recovered.

### ICANN registration information

| Field | Value |
|---|---|
| Created | 24 October 2008 |
| Last updated | 25 October 2026 |
| Expires | 24 October 2027 |
| Name servers | NS1 and NS2 at PEACESOFT.IN |
| Status | Client delete, renew, transfer, and update prohibited |

This is an established business domain, not a throwaway one. It was most likely used because it already had a clean reputation. The record was updated on 25 October 2026, after the email, but the cause is not known.

## Attachment Analysis

The email carries three attachments, all Apple configuration profiles (`.mobileconfig`). They were read as text only and never installed or opened on a device.

| Attachment | Size | SHA-256 | VirusTotal |
|---|---|---|---|
| `emails-quarksseg.mobileconfig` | 5,396 bytes | `8c0013f6ee4fe229f567469ed3f1bdaf2ee6a7a4b39a04ed28df38fa25287dfb` | 0 of 59 detections |
| `carddav-quarksseg.mobileconfig` | 5,230 bytes | `783cdb7425fbc29f5e35801d38a4782040da7f50e74d78de4b56eaa532eda82a` | 0 of 61 detections |
| `caldav-quarksseg.mobileconfig` | 6,350 bytes | `ee8f15128560c2b2b4ee242026b2a2880ee604fe8489abb999ac43c969cfcdce` | 0 of 61 detections |

### What the profiles contain

Decoded in CyberChef, the profiles are digitally signed and set up accounts for one mailbox, `blutrgr@eu40.escolagranderio.com.br`, on the Brazilian mail server `mail.escolagranderio.com.br`:

| Profile | Contents |
|---|---|
| `emails-…` | A calendar (CalDAV) account on port 2080 over SSL |
| `carddav-…` | A contacts (CardDAV) account for the same mailbox |
| `caldav-…` | An IMAP email account, incoming port 993 and outgoing port 465, both over SSL |

None of the profiles contains a password; installing one would prompt for it. The identifiers (`cpanel.mail.org…`) show that cPanel generated them. The file names do not match the contents: the file called "emails" holds the calendar profile and the file called "caldav" holds the email profile.

### Reuse of the files

VirusTotal already knows all three hashes under different names (`emails-certificadoparaevento.mobileconfig` and the matching `carddav-` and `caldav-` names), last analysed 5 to 7 months earlier. The community scores are negative (−42 and −43 on two of them), but the community comments were not reviewed. The same three files appear in at least three other Phishing Pot samples (9923, 10043 and 10121) that carry the same style of Microsoft lure from different sender domains, which makes the hashes a useful campaign indicator.

### Assessment

The attachments are not malware in the usual sense: they contain no scripts and no payloads, and antivirus engines detect nothing. Why they were attached is **not determined**. They may be reused artifacts, or decoys that make the email look more substantial. This is not confirmed.

## Indicators of Compromise (IOCs)

| Type | Value (defanged) | Note |
|---|---|---|
| URL | `hxxps://www[.]v2[.]brighthomedaycare[.]com/` | Phishing link |
| Sender address | `co@brighthomedaycare[.]com` | Likely a compromised or abused business account |
| Linked hostname | `www[.]v2[.]brighthomedaycare[.]com` | Resolved by VirusTotal to 129.121.86.219. Check before blocking, as it may be shared hosting |
| Origin host | `EC2AMAZ-A9QNUAT` | Windows EC2 hostname in the first hop |
| Origin address | `2a05:d01c:f37:6300:569f:d15f:9569:3e0b` | Amazon (AS 16509). Likely short-lived |
| Relay IP | 209.85.128.68 | Google mail server. Do not block |
| Subject | Terms Update Effective Mon, March 30, 2026 | Useful for a mail search |
| Decoy To address | `customer@postmaster[.]microsoft365[.]com` | Suggests Bcc mass mailing |
| X-Mailer string | `Gmail Default Mailer`s - **…**` | Custom tool marker |
| Attachment hash | `8c0013f6ee4fe229f567469ed3f1bdaf2ee6a7a4b39a04ed28df38fa25287dfb` | Reused in other samples |
| Attachment hash | `783cdb7425fbc29f5e35801d38a4782040da7f50e74d78de4b56eaa532eda82a` | Reused in other samples |
| Attachment hash | `ee8f15128560c2b2b4ee242026b2a2880ee604fe8489abb999ac43c969cfcdce` | Reused in other samples |

**Note:** Block the sender address and the specific URL. Do not block Google addresses. Do not block the whole `brighthomedaycare.com` website without contacting the owner, because it is probably a victim whose account or site was abused.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1566.002 Phishing: Spearphishing Link | Link-based lure imitating a trusted vendor |
| Reconnaissance | T1598.003 Phishing for Information: Spearphishing Link | The page is meant to collect sign-in and payment details |
| Defense Evasion | T1656 Impersonation | Disguised "Microsoft" display name and a logo built from table cells |

## Risk Assessment

A recipient who signs in on the fake page would give away their Microsoft credentials and could expose a payment card. Stolen Microsoft 365 credentials can lead to mailbox takeover and further phishing from a trusted account. The compromised sending account and website also belong to a real business that is being abused.

## Detection Opportunities

### Mail gateway or SIEM detection

- Alert on display names that contain the word "Microsoft" or other brands where the sending domain is unrelated
- Flag invisible or look-alike Unicode characters in display names
- Flag external mail with `.mobileconfig` attachments, which are rare in business mail
- Match the subject pattern and the shared attachment hashes
- Flag a decoy To address with an unrelated sender

### Network and proxy monitoring

- Block the phishing URL and look for visits to `www.v2.brighthomedaycare.com`
- Alert on billing or sign-in lures that link to an unrelated small-business domain

### Endpoint management

- Restrict installation of configuration profiles on managed Apple devices

## Recommended Response

| Action | Detail |
|---|---|
| Contain | Block the sender address, the phishing URL, and the attachment hashes, and remove the email from all mailboxes |
| Investigate | Search mail logs for the subject and sender, and proxy and DNS logs for `www.v2.brighthomedaycare.com`, to find recipients who clicked |
| Remediate | If anyone entered credentials, reset their password, revoke sessions, review sign-in activity, and warn them to watch card activity. Tell users not to install the profiles |
| Prevent | Notify the owner of `brighthomedaycare.com` so they can secure the mailbox and site. Report the Amazon EC2 address to AWS abuse. User awareness on billing and terms-update lures |

## 5 Ws Summary

| Field | Answer |
|---|---|
| Time of Activity | 30 March 2026, about 17:45 UTC |
| Affected Entities | The recipient mailbox. Other recipients are unknown. The owner of `brighthomedaycare.com` is likely a victim |
| Reason for Classification | A billing sign-in lure, a disguised Microsoft display name, an authenticated send from an unusual host, a link to an unrelated domain flagged by 2 vendors, and unexplained reused attachments |
| Reason for Escalating | The email targets Microsoft credentials and payment details, and passes every authentication check so filters may deliver it |
| Remediation Actions | Block the sender and URL, remove the email, check logs for clicks, reset credentials if needed, notify the domain owner |
| Attack Indicators | www[.]v2[.]brighthomedaycare[.]com, co@brighthomedaycare[.]com, the three attachment hashes |

## Limitations

- The landing page was never observed. urlscan failed twice and VirusTotal recorded no response, so the report cannot say what the page asked for.
- Whether the sending account was compromised is an inference from the headers, not a confirmed fact.
- The purpose of the three configuration profiles is not determined. The VirusTotal community comments and relations were not reviewed, and the signing certificate was not analysed.
- The scan of the page was run publicly as well as unlisted. In a real investigation, public scans can expose the URL.
- No evidence in this sample shows whether any recipient clicked.

## Evidence

Screenshots stored in `Evidence/Case_03/`.

### Sender, headers, and authentication

**1A. From line and the origin hop** (`01A_From_and_Origin_Hop.png`)

![From line and origin hop](../Evidence/Case_03/01A_From_and_Origin_Hop.png)

**1B. Subject, date, and mailer** (`01B_Subject_Date_Mailer.png`)

![Subject, date and mailer](../Evidence/Case_03/01B_Subject_Date_Mailer.png)

**2. SPF, DKIM, and DMARC results** (`02_Authentication_Results.png`)

![Authentication results](../Evidence/Case_03/02_Authentication_Results.png)

**3A. Display name decoded in CyberChef** (`03A_Display_Name_Decoded_1.png`)

![Display name decoded, part 1](../Evidence/Case_03/03A_Display_Name_Decoded_1.png)

**3B. Display name decoded in CyberChef, continued** (`03B_Display_Name_Decoded_2.png`)

![Display name decoded, part 2](../Evidence/Case_03/03B_Display_Name_Decoded_2.png)

### Email body

**4. Email body HTML with the link** (`04_Email_Body_HTML.png`)

![Email body HTML](../Evidence/Case_03/04_Email_Body_HTML.png)

### Link and domain checks

**5A. VirusTotal URL detections** (`05A_VirusTotal_URL_Detection.png`)

![VirusTotal URL detections](../Evidence/Case_03/05A_VirusTotal_URL_Detection.png)

**5B. VirusTotal URL details** (`05B_VirusTotal_URL_Details.png`)

![VirusTotal URL details](../Evidence/Case_03/05B_VirusTotal_URL_Details.png)

**6. VirusTotal domain detections** (`06_VirusTotal_Domain_Detection.png`)

![VirusTotal domain detections](../Evidence/Case_03/06_VirusTotal_Domain_Detection.png)

**7. VirusTotal domain details** (`07_VirusTotal_Domain_Details.png`)

![VirusTotal domain details](../Evidence/Case_03/07_VirusTotal_Domain_Details.png)

**8. urlscan public scan** (`08_URLScan_Public_Result.png`)

![urlscan public scan](../Evidence/Case_03/08_URLScan_Public_Result.png)

**9. urlscan unlisted scan** (`09_URLScan_Unlisted_Result.png`)

![urlscan unlisted scan](../Evidence/Case_03/09_URLScan_Unlisted_Result.png)

**10. ICANN domain registration data** (`10_ICANN_Domain_Lookup.png`)

![ICANN domain lookup](../Evidence/Case_03/10_ICANN_Domain_Lookup.png)

### Attachment 1: emails-quarksseg.mobileconfig

**11. Attachment headers** (`11_Attachment_01_Headers.png`)

![Attachment 1 headers](../Evidence/Case_03/11_Attachment_01_Headers.png)

**12A. Decoded CalDAV settings** (`12A_Decoded_CalDAV_Settings.png`)

![Decoded CalDAV settings](../Evidence/Case_03/12A_Decoded_CalDAV_Settings.png)

**12B. Decoded profile metadata** (`12B_Decoded_Profile_Metadata.png`)

![Decoded profile metadata](../Evidence/Case_03/12B_Decoded_Profile_Metadata.png)

**13. SHA-256 of attachment 1** (`13_Attachment_01_SHA256.png`)

![Attachment 1 SHA-256](../Evidence/Case_03/13_Attachment_01_SHA256.png)

**14. VirusTotal result for attachment 1** (`14_VirusTotal_Mobileconfig_Hash_Analysis.png`)

![VirusTotal attachment 1](../Evidence/Case_03/14_VirusTotal_Mobileconfig_Hash_Analysis.png)

### Attachment 2: carddav-quarksseg.mobileconfig

**15. Attachment headers** (`15_Attachment_02_Headers.png`)

![Attachment 2 headers](../Evidence/Case_03/15_Attachment_02_Headers.png)

**16. Decoded CardDAV settings** (`16_Decoded_CardDAV_Settings.png`)

![Decoded CardDAV settings](../Evidence/Case_03/16_Decoded_CardDAV_Settings.png)

**17. Decoded profile metadata** (`17_Decoded_CardDAV_Profile_Metadata.png`)

![Decoded CardDAV metadata](../Evidence/Case_03/17_Decoded_CardDAV_Profile_Metadata.png)

**18. SHA-256 of attachment 2** (`18_Attachment_02_SHA256.png`)

![Attachment 2 SHA-256](../Evidence/Case_03/18_Attachment_02_SHA256.png)

**19. VirusTotal result for attachment 2** (`19_VirusTotal_CardDAV_Hash_Analysis.png`)

![VirusTotal attachment 2](../Evidence/Case_03/19_VirusTotal_CardDAV_Hash_Analysis.png)

### Attachment 3: caldav-quarksseg.mobileconfig

**20. Attachment headers** (`20_Attachment_03_Headers.png`)

![Attachment 3 headers](../Evidence/Case_03/20_Attachment_03_Headers.png)

**21. Decoded IMAP email settings** (`21_Decoded_IMAP_Email_Settings.png`)

![Decoded IMAP settings](../Evidence/Case_03/21_Decoded_IMAP_Email_Settings.png)

**22. Decoded profile metadata** (`22_Decoded_IMAP_Profile_Metadata.png`)

![Decoded IMAP metadata](../Evidence/Case_03/22_Decoded_IMAP_Profile_Metadata.png)

**23. SHA-256 of attachment 3** (`23_Attachment_03_SHA256.png`)

![Attachment 3 SHA-256](../Evidence/Case_03/23_Attachment_03_SHA256.png)

**24. VirusTotal result for attachment 3** (`24_VirusTotal_IMAP_Attachment_Hash_Analysis.png`)

![VirusTotal attachment 3](../Evidence/Case_03/24_VirusTotal_IMAP_Attachment_Hash_Analysis.png)

### Origin address

**25. VirusTotal result for the origin address** (`25_VirusTotal_Origin_IP_Analysis.png`)

![VirusTotal origin address](../Evidence/Case_03/25_VirusTotal_Origin_IP_Analysis.png)

## Lessons Learned

1. All authentication checks can pass and the email can still be phishing. Authentication tells you which infrastructure sent a message, not whether the sender is legitimate. Check where the message actually originated.
2. A first hop that does not fit the sender (a Windows EC2 host logging in to Gmail for a daycare) is stronger evidence than the authentication results.
3. Attackers disguise display names with look-alike letters and invisible characters. Decode suspicious names instead of reading them at face value.
4. An attachment that is harmless to antivirus can still matter. Hash it, check what is known, and say plainly when its purpose is undetermined.
5. Compare a sample with others to find a campaign. Identical attachment hashes in several samples show the same operator behind different sender domains.
6. Use unlisted or private scans in real investigations, because a public scan exposes the URL you are investigating.
7. In raw email text, a trailing `=` is a line-break marker and should be removed before hashing or recording a URL or encoded value.
