# Cyber Threat Hunting with Splunk – Part 2: Initial Access

## Summary
In this lesson we continue cyber threat hunting using Splunk and the **BOTS v2 dataset**.  
The prior exercise covered the **Reconnaissance** phase. This one focuses on **Initial Access**, specifically spear phishing.


## Objectives
1. Continued practical familiarization using Splunk.  
2. Analyze initial access of an emulated APT campaign dataset.  
3. Create hypotheses and hunt plans from threat intelligence reports.  
4. Identify indicators of compromise.  


## Scenario
Law enforcement warns of an ongoing spearphishing campaign in our industry sector.  
We must **develop a hypothesis, plan, and execute** a Splunk hunt.

### Threat Intelligence Report Excerpt
- Vector: **Zipped spearphishing attachments (T1566.001)**  
- Execution: **User Execution (T1204.002)**  
- Lures: **Financial docs (invoices, receipts, requisitions, etc.)**

### Available Source Types
To check sourcetypes in Splunk:

spl
index=botsv2

`| metadata type=sourcetypes index=botsv2`

### Key Sourcetypes

Two key sourcetypes:
	•	Sysmon logs
	•	SMTP (email)

![Sysmon and SMTP](./images/sourcetypes.png)

### Hypothesis

Adversaries launched spearphishing in August, delivering malicious attachments.
At least one user executed the attachment.


Plan of Action
	1.	Review stream:smtp logs for August.
	2.	Pivot to Sysmon logs for process creation (Event ID 1).

Initial Query

Set time picker → August 2017

![Time picker](./images/timepicker_aug2017.png)

Our first query will be for smtp logs.

`index=botsv2 sourcetype=stream:smtp`

![Smtp search](./images/smtp_search.png)

Scroll to the bottom and select “more fields.”

![More fields](./images/more_fields.png)

Field Selection

Splunk doesn’t auto-display all fields.
At minimum, select:
	`•	receiver
	•	sender
	•	src_ip
	•	subject
	•	attach_filename{}
	•	attach_type{}
	•	attach_size{}
	•	attach_content_md5_hash{}`

![Select fields](./images/select_fields.png) 

Suspicious Attachment
	`•	Double-click attach_filename{}
	 •	Suspicious file: Invoice.zip`

![Select fields](./images/invoice_zip_list.png)

Filtered down to 4 events.

![Four events](./images/four_events.png)

Query: [`email_fields_invoice_zip.spl`](./queries/splunk/email_fields_invoice_zip.spl)

Result:

•	Same sender, subject, filename, size, hash, type across all 4 emails.

![Common denominators](./images/common_denominators.png) 

OSINT (ipinfo.io): last hop = Microsoft mail server

![Microsoft server](./images/ms_mail_server.png) 

Switch to Events → view headers.

![Events view](./images/events_view.png)

We can see the contents of the email, including the header, by clicking the drop down at “content”.

![Email contents](./images/email_contents.png)

Copy and paste the email header.

![Copy email header](./images/email_header.png)

MX Toolbox: origin = 185.83.51.21

![Mxtoolbox origin](./images/mxtoolbox_origin.png)

Message-ID

Unique identifier, logged by servers. Useful for tracking.

![Message id](./images/message_id.png)

Received

Each hop logs IP, server, timestamp.

![Received chain](./images/received_chain.png)

Sender Policy Framework (SPF)

Validates sending IP ↔ domain relationship.

![Spf](./images/spf.png)

DomainKeys Identified Mail (DKIM)

Digital signature validation.

![Dkim](./images/dkim.png)

ARC (Authenticated Record Chain)

Preserves auth results across intermediaries.

![Arc](./images/arc_headers.png)

DMARC

Builds on SPF + DKIM with policies & reporting.

Return-Path

Specifies where bounces go.

![Arc](./images/return_path.png)

Online Email Analyzers
	•	MX Toolbox (https://mxtoolbox.com/EmailHeaders.aspx)

![Mxtoolbox](./images/mxtoolbox_tool.png)

•	Microsoft Analyzer (https://mha.azurewebsites.net/)

![Microsoft Analyzer](./images/Microsoft_analyzer.png)

Analysis Tips
	•	Trace Received lines → origin server.
	•	Check consistency (Return-Path, From, Received).
	•	Verify timestamps, SPF, DKIM.
	•	Use IP lookups.
	•	Watch for spoofing, base64, odd formatting.

Back to Our Investigation

From OSINT (ipinfo.io)
Pivot: IP 185.83.51.21 → domain ymlp.com (email service).

![ipinfo ympl](./images/ipinfo_ymlp.png)

We see the domain for that IP address is ymlp.com. We can use OSINT to discover that YMLP is an email sending service.

![ymlp site](./images/ymlp_site.png)

Unfortunately, this will not tell us much as far as attribution, since this service could be used by anybody.

Identical email content across 4 emails.

![Email identical](./images/email_identical.png)

Pivot on Sender

Query: [`sender_pivot.spl`](./queries/splunk/sender_pivot.spl)

Result: same sender targeted recipients 13 days earlier.

![Sender](./images/sender_13days_prior.png)

![Sender](./images/sender_13days_prior.png)

Further analysis shows that the sender used the previously discovered email sending service in the first set of emails.

![Earlier service ](./images/earlier_service.png)

Suspicious text file + base64 in body.

![suspicious base64 ](./images/suspicious_base64.png)

Decoded in CyberChef → malware.

![suspicious base64 ](./images/cyberchef_removed.png)

Based on our analysis above, this is what we currently know.

- Phishing was attempted twice.
    
    First attempt was unsuccessful.
    
    Second attempt delivery succeeded.
    
- Sender IP: 185.83.51.21
- Sender Name is Jim Smith <jsmith@urinalysis.com>
- Phishing targeted the same four recipients both times.
- Subject: Invoice
- Body was identical
- Emails were sent in close proximity, but individually
- Attachment was the same for each recipient.

Below is a graphical representation of what we currently know.

![Graphic ](./images/graphical_representation.png)

User Execution

To confirm whether any of the four targeted users executed the phishing attachment, we focus on activity from 23 August, the date of the attack. Running a query without specifying a sourcetype helps reveal which log sources reference invoice.zip. ⚠️ Note: in enterprise environments, avoid broad queries without sourcetype filters unless the timeframe is tightly constrained, to maintain efficiency.

Query: [`broad_invoice_zip_no_sourcetype.spl`](./queries/splunk/broad_invoice_zip_no_sourcetype.spl) 

![Invoice query ](./images/query_invoice_zip.png)

All logs tie to host wrk-btun (Billy Tun).

![Host drilldown ](./images/host_drilldown.png)

From registry: WINWORD opened invoice.doc from extracted zip.

![Registry ](./images/registry_winword.png)

Query: [`sysmon_invoice_zip_table.spl`](./queries/splunk/sysmon_invoice_zip_table.spl)

![Sysmon table1 ](./images/sysmon_table1.png)

![Sysmon table2 ](./images/sysmon_table2.png)

We can dig deeper by changing the time picker to the time of the first Sysmon event.

![Time picker ](./images/timepicker_sysmon.png)

Drill into timeline: [`host_reverse_timeline.spl`](./queries/splunk/host_reverse_timeline.spl)  

Find base64-encoded PowerShell.

![Encoded base64 ](./images/encoded_ps.png)

Decoded → malicious script.

![Encoded base64 ](./images/decoded_ps.png)

Key Actions by Script:
	•	Disable AMSI
	•	Ignore SSL validation
	•	Create WebClient
	•	Set user-agent + cookies
	•	Contact C2 → 45.77.65.211
	•	Download, decrypt, execute payload

Conclusion

Findings:
	•	Two phishing waves (1 failed, 1 delivered).
	•	Same sender: Jim Smith <jsmith@urinalysis.com>
	•	IPs: 185.83.51.21, 45.77.65.211
	•	Targeted same 4 users.
	•	Execution confirmed on host wrk-btun (Billy Tun).
	•	Dropped malicious PowerShell → outbound C2.

![Findings graph ](./images/findings_graph.png)
 

References
	•	Dataset: Splunk BOTS v2 (https://bots.splunk.com/)
	•	Tools: MX Toolbox, CyberChef, ipinfo.io    
