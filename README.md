\# Network Reconnaissance Detection Lab



A detection engineering lab that simulates 5 different Nmap

scan types and builds SIEM queries to detect reconnaissance

activity while reducing false positives.



\## Lab Architecture



| Component | Role | Tool |

|-----------|------|------|

| Windows 11 (host) | Victim + SIEM platform | Elastic SIEM, Winlogbeat |

| Kali Linux (VM) | Attacker machine | Nmap |

| Windows Firewall | Traffic capture | pfirewall.log |

| VirtualBox | Hypervisor | Host-only network |



\*\*Network:\*\*

\- Attacker: 192.168.56.101 (Kali Linux VM)

\- Victim/SIEM: 192.168.56.1 (Windows 11 host)



\## Attack Simulations



| Scan Type | Command | Purpose |

|-----------|---------|---------|

| SYN Stealth | nmap -sS | Most common attacker scan |

| TCP Connect | nmap -sT | Full TCP connection scan |

| NULL Scan | nmap -sN | Evasion technique |

| FIN Scan | nmap -sF | Firewall bypass attempt |

| XMAS Scan | nmap -sX | Sets FIN, PSH, URG flags |



\## Detection Queries (KQL)



| Query | Purpose | Results |

|-------|---------|---------|

| event.code: 5152 AND message: "192.168.56.101" | All recon traffic | 24 hits |

| event.code: 5152 AND message: "192.168.56.101" AND message: "ALLOW TCP" | TCP scan detection | 24 hits |

| event.code: 5152 AND message: "192.168.56.101" AND message: "445" | SMB port probe | 5 hits |

| event.code: 5152 AND message: "192.168.56.101" AND message: "135" | RPC port probe | 16 hits |

| event.code: 5152 AND message: "192.168.56.101" AND message: "RECEIVE" | Rapid scan pattern | 24 hits |



\## Detection Engineering Approach



1\. Enabled Windows Firewall logging for dropped and allowed packets

2\. Imported firewall logs into Windows Event Log using PowerShell

3\. Winlogbeat shipped events to Elasticsearch as Event ID 5152

4\. Built KQL queries in Kibana for each scan type

5\. Tuned queries to reduce false positives by filtering on attacker IP



\## False Positive Reduction



| Technique | Description |

|-----------|-------------|

| Source IP filter | Only alert on non-trusted subnets |

| Port threshold | Alert only when >10 ports hit from same IP |

| Time window | Alert when >5 connections in 60 seconds |

| Protocol filter | Focus on TCP/UDP, ignore ICMP |



\## MITRE ATT\&CK Coverage



| Technique | ID | Detection Method |

|-----------|-----|-----------------|

| Network Service Discovery | T1046 | Event 5152 + port 445/135 |

| Active Scanning | T1595 | Event 5152 + high volume |

| OS Fingerprinting | T1592 | Event 5152 + multiple ports |



\## Incident Report



\- \[Detection Engineering Report](reports/Detection-Report-001.md)



\## Tools Used



Nmap · Elastic SIEM · Kibana · Winlogbeat · Windows Firewall ·

KQL · Kali Linux · VirtualBox · MITRE ATT\&CK

