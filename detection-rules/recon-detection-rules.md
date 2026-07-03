\# Reconnaissance Detection Rules



\## Rule 1 — All Recon Traffic

\*\*Name:\*\* Recon-001-All-Traffic

\*\*Severity:\*\* Medium

\*\*Query:\*\*

event.code: 5152 AND message: "192.168.56.101"



\## Rule 2 — TCP Scan Detection

\*\*Name:\*\* Recon-002-TCP-Scan

\*\*Severity:\*\* Medium

\*\*Query:\*\*

event.code: 5152 AND message: "192.168.56.101" AND message: "ALLOW TCP"



\## Rule 3 — SMB Port Probe

\*\*Name:\*\* Recon-003-SMB-Probe

\*\*Severity:\*\* High

\*\*Query:\*\*

event.code: 5152 AND message: "192.168.56.101" AND message: "445"

\*\*MITRE:\*\* T1046



\## Rule 4 — RPC Port Probe

\*\*Name:\*\* Recon-004-RPC-Probe

\*\*Severity:\*\* Medium

\*\*Query:\*\*

event.code: 5152 AND message: "192.168.56.101" AND message: "135"

\*\*MITRE:\*\* T1046



\## Rule 5 — Rapid Scan Pattern

\*\*Name:\*\* Recon-005-Rapid-Scan

\*\*Severity:\*\* High

\*\*Query:\*\*

event.code: 5152 AND message: "192.168.56.101" AND message: "RECEIVE"

\*\*MITRE:\*\* T1595

