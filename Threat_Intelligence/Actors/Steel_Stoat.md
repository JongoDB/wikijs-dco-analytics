---
title: Steel Stoat
type: actor
importable: true
exportable: true
last_reviewed: 2025-01-20
mitre_ids: ["T1071", "T1071.001", "T1027", "T1033", "T1041", "T1053.004", "T1053.005", "T1059", "T1059.002", "T1059.004", "T1071.001", "T1204.002", "T1543.003", "T1543.004", "T1547", "T1548", "T1564.001", "T1566.002", "T1573", "T1573.001", "T1583", "T1583.001", "T1583.006", "T1587.001", "T1588.003", "T1588.004"]
---

# Steel Stoat

## Overview

Steel Stoat (SS) is a highly adaptable threat actor group known for utilizing a mix of custom malware, commodity tools, and publicly known exploits. The group demonstrates sophisticated capabilities in network infiltration, persistence, and data exfiltration.

## Attribution

### Group Profile
- **Group Name**: Steel Stoat (SS)
- **Country of Origin**: North Korea
- **Motivation**: Financial gain, espionage
- **Target Sectors**: Cryptocurrency, financial services, critical infrastructure
- **Active Since**: 2018

### Threat Level
- **Sophistication**: Very High
- **Resources**: State-sponsored
- **Persistence**: Long-term operations
- **Stealth**: Advanced evasion techniques

## Tactics, Techniques, and Procedures (TTPs)

### Initial Access
- **Supply Chain Compromise**: Targeting software supply chains
- **Spearphishing**: Targeted phishing campaigns
- **Exploit Public-Facing Application**: Web application vulnerabilities

### Execution
- **Command and Scripting Interpreter**: PowerShell, Windows Command Shell
- **Scheduled Task/Job**: Cron jobs, scheduled tasks
- **User Execution**: Malicious file execution

### Persistence
- **Boot or Logon Autostart Execution**: Registry run keys, startup folders
- **Create or Modify System Process**: Windows services, launchd
- **Hijack Execution Flow**: DLL sideloading, executable hijacking

### Privilege Escalation
- **Abuse Elevation Control Mechanism**: UAC bypass techniques
- **Process Injection**: DLL injection into privileged processes

### Defense Evasion
- **Obfuscated Files or Information**: Encrypted payloads, packed executables
- **Hide Artifacts**: Hidden files and directories
- **Impair Defenses**: Disabling security tools, clearing logs

### Credential Access
- **OS Credential Dumping**: LSASS memory dumping, SAM database access
- **Steal or Forge Kerberos Tickets**: Kerberoasting, golden ticket attacks

### Discovery
- **System Owner/User Discovery**: whoami, net user commands
- **Network Service Scanning**: Port scanning, service enumeration
- **System Information Discovery**: System profiling, configuration enumeration

### Collection
- **Screen Capture**: Screenshot tools, screen recording
- **Data from Information Repositories**: Database queries, file system access

### Command and Control
- **Application Layer Protocol**: HTTP/HTTPS, DNS
- **Encrypted Channel**: TLS, custom encryption
- **Proxy**: SOCKS proxies, HTTP proxies

### Exfiltration
- **Exfiltration Over C2 Channel**: Data theft through C2 communication
- **Data Compressed**: Archive files, compressed data

### Impact
- **Data Encrypted for Impact**: Ransomware, data destruction
- **Service Stop**: Stopping critical services

## Malware Families

### Primary Malware
- **RATANKBA**: Custom RAT with advanced capabilities
- **WannaCry**: Ransomware for financial gain
- **Clop**: Ransomware targeting critical infrastructure
- **DarkManila**: Backdoor with persistence capabilities

### Tools
- **Impacket**: Post-exploitation toolkit
- **Scanbox**: Web profiling tool
- **Tomcat Backdoor**: Web shell for persistent access

## Target Sectors

### Primary Targets
- **Cryptocurrency**: Exchanges, wallets, mining operations
- **Financial Services**: Banks, payment processors
- **Critical Infrastructure**: Power grids, water systems

### Geographic Focus
- **Global**: International targets for financial gain
- **Asia-Pacific**: Regional focus for espionage

## Indicators of Compromise (IOCs)

### Network Indicators
- **C2 Domains**: Suspicious domains associated with SS operations
- **IP Addresses**: Known SS infrastructure IP addresses
- **Ports**: Commonly used ports for C2 communication

### File Indicators
- **File Hashes**: SHA-256 hashes of SS malware samples
- **File Names**: Common file names used by SS tools
- **Registry Keys**: Registry entries created by SS malware

### Behavioral Indicators
- **Network Patterns**: Unusual network traffic patterns
- **Process Behavior**: Suspicious process creation and execution
- **File System Changes**: Unusual file creation and modification

## Detection Strategies

### Network Detection
```suricata
# RATANKBA C2 Communication
alert tcp any any -> any any (msg:"SS - RATANKBA C2 Communication"; content:"|52 41 54 41 4E 4B 42 41|"; flow:established,to_server; sid:2025103001; rev:1;)

# WannaCry SMB Exploit
alert ip any any -> any any (msg:"SS - WannaCry SMB Exploit Attempt"; content:"|FF|SMB"; depth:1; flow:established,to_server; sid:2025103002; rev:1;)
```

### Host Detection
```powershell
# Tomcat Backdoor Detection
Get-Process | Where-Object {$_.ProcessName -match "tomcat" -and $_.CommandLine -match "backdoor"}

# Clop Ransomware Detection
Get-ChildItem -Path "C:\" -Recurse -Filter "*.clop" -ErrorAction SilentlyContinue
```

## Mitigation Strategies

### Prevention
- **Network Segmentation**: Isolate critical systems
- **Access Controls**: Implement strict access controls
- **Security Awareness**: Train personnel on phishing and social engineering

### Detection
- **Endpoint Protection**: Deploy EDR solutions
- **Network Monitoring**: Monitor for suspicious network traffic
- **Log Analysis**: Regular analysis of security logs

### Response
- **Incident Response**: Have procedures for SS incidents
- **Forensic Analysis**: Preserve evidence for investigation
- **Recovery**: Use clean backups for system recovery

## Related Documentation

- [SS Hunt Report](../../Hunt_Playbooks/Active-Mission/Steel_Stoat/Hunt_Report.md)
- [SS Suricata Rules](../../Detections/Network/SS_Suricata_Rules.md)
- [SS Windows Host Detections](../../Detections/Host/Windows/SS_Windows_Host_Detections.md)

## References

- [CISA Alert - North Korean State-Sponsored Threats](https://www.cisa.gov/news-events/cybersecurity-advisories/)
- [MITRE ATT&CK - Steel Stoat](https://attack.mitre.org/groups/)
- [FBI Guidance - North Korean Cyber Threats](https://www.fbi.gov/)
