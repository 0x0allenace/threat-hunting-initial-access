# HOW TO RUN SPL QUERIES

This short guide explains how to run the Splunk (`.spl`) queries in `hunts/part2_initial_access/queries/splunk/` and how to follow the hunt workflow in `HUNT-Part2-Initial-Access.md`.

> Assumption: you have access to a Splunk instance with the **botsv2** index (or equivalent test data). Adjust `index=` and `sourcetype=` values if your environment uses different names.


## Quick principles / safety
- **Always set the time picker** before running queries. For these exercises use:
  - **August 2017** (whole exercise), or
  - **23 Aug 2017** (user execution timeline).
- **Avoid running queries without a sourcetype** unless the time window is very small (minutes–hours). Broad sourceless queries on large ranges are slow and may strain production systems.
- Copy queries into the Splunk Search bar — do **not** run raw files on production without review.
- Use the `.spl` files as templates; adapt fields (field names and sourcetypes) to your deployment.


## Files & where to find them
- Main walkthrough:  
  `hunts/part2_initial_access/HUNT-Part2-Initial-Access.md`
- Queries folder:  
  `hunts/part2_initial_access/queries/splunk/`
- Example query files:
  - `email_fields_invoice_zip.spl` — lookup emails with `invoice.zip`
  - `sender_pivot.spl` — pivot on the sender to find previous deliveries
  - `broad_invoice_zip_no_sourcetype.spl` — broad inventory for `invoice.zip` (use with tight time window)
  - `sysmon_invoice_zip_table.spl` — show Sysmon event table for `invoice.zip`
  - `host_reverse_timeline.spl` — host timeline (reverse order)


## How to open and run a `.spl` file
1. Open the file in your editor (VS Code / GitHub) and copy its contents.
2. In Splunk Web, set the time picker to the intended window (e.g., `23 Aug 2017 00:00:00` → `23 Aug 2017 23:59:59`).
3. Paste the query into the Search bar and run.
4. If a query references a field or sourcetype that doesn't exist in your environment, update it (e.g., `sourcetype=stream:smtp` → your mail sourcetype).


## Recommended run order (matching the hunt)
1. **Inventory sourcetypes** (quick check)
   spl
   | tstats count where index=botsv2 by sourcetype

	2.	Search SMTP for invoice.zip (email fields)
File: email_fields_invoice_zip.spl
Purpose: find attach_filename{} = invoice.zip, list sender/receiver/hash
	3.	Pivot on sender
File: sender_pivot.spl
Purpose: find earlier deliveries from the same sender
	4.	Broad inventory for invoice.zip (small window only)
File: broad_invoice_zip_no_sourcetype.spl
Purpose: discover which sourcetypes recorded the filename (registry, sysmon, etc.)
	5.	Sysmon table for invoice events
File: sysmon_invoice_zip_table.spl
Purpose: confirm process creation events and users
	6.	Host timeline (reverse)
File: host_reverse_timeline.spl
Purpose: view the execution order on the host
	7.	Pivot to network / C2 indicators (use discovered IPs and domains for further queries)

Examples (copy-paste-safe)
	•	Find email events with invoice.zip (time picker = 23 Aug 2017):

    Spl

    index=botsv2 sourcetype=stream:smtp "attach_filename{}"="invoice.zip"
| table _time, receiver, sender, src_ip, subject, attach_filename{}, attach_type{}, attach_size{}, attach_content_md5_hash{}

	•	Broad inventory for invoice.zip (ONLY use with tight time window):

    index=botsv2 invoice.zip sourcetype!="stream:smtp"

	•	Sysmon events showing file/process activity for invoice.zip:

    index=botsv2 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" invoice.zip
| table _time, Computer, User, EventCode, Image, ParentImage, CommandLine

Helpful tips
	•	If a query returns no results, widen the time window slightly (minutes → hours), then narrow again once you find hits.
	•	Use convert ctime(_time) or | eval time=strftime(_time, "%Y-%m-%d %H:%M:%S") to show readable timestamps.
	•	Save useful searches as Splunk saved searches / alerts after you’ve tuned filters and thresholds.
	•	Keep an artifacts/iocs.txt file handy — copy IPs/hashes into Splunk lookups or blocklists as appropriate.


Viewing .spl files from GitHub
	•	GitHub will render .spl files as text in-browser. Click the file link from the repo to view the query, then copy → paste into Splunk.
	•	If you prefer viewing raw text directly: use the Raw button in GitHub file view or open the file path:
https://github.com/<your-repo>/blob/main/hunts/part2_initial_access/queries/splunk/<file>.spl


Troubleshooting
	•	No hits: verify index, sourcetype, and time range.
	•	Slow query: add sourcetype= or tighten time picker.
	•	Field missing: run index=botsv2 sourcetype=<candidate> | head 10 | table * to inspect fields available in that sourcetype.

