---
title: Shotgun Tiger
type: actor
importable: true
exportable: true
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1003.006", "T1016", "T1033", "T1041", "T1047", "T1049", "T1053.005", "T1055.001", "T1059", "T1059.003", "T1070.006", "T1071", "T1071.001", "T1071.004", "T1090", "T1102.002", "T1218.011", "T1543.003", "T1547", "T1550", "T1560"]
---

# Shotgun Tiger

## Overview

Shotgun Tiger (ST) is a sophisticated threat actor group known for targeting maritime and logistics organizations. The group employs a diverse toolkit of custom malware and publicly available tools to conduct espionage and data theft operations.

## Attribution

### Group Profile
- **Group Name**: Shotgun Tiger (ST)
- **Country of Origin**: China
- **Motivation**: Espionage, intellectual property theft
- **Target Sectors**: Maritime, logistics, transportation
- **Active Since**: 2019

### Threat Level
- **Sophistication**: High
- **Resources**: State-sponsored
- **Persistence**: Long-term operations
- **Stealth**: Advanced evasion techniques

## Tactics, Techniques, and Procedures (TTPs)

### Initial Access
- **Phishing**: Spearphishing campaigns targeting maritime organizations
- **Supply Chain**: Compromising software supply chains
- **Vulnerability Exploitation**: Exploiting known vulnerabilities in maritime systems

### Execution
- **Command and Scripting Interpreter**: PowerShell, Windows Command Shell
- **Scheduled Task/Job**: Cron jobs, scheduled tasks
- **Process Injection**: DLL injection, process hollowing

### Persistence
- **Boot or Logon Autostart Execution**: Registry run keys, startup folders
- **Create or Modify System Process**: Windows services, launchd
- **Hijack Execution Flow**: DLL sideloading, executable hijacking

### Privilege Escalation
- **Process Injection**: DLL injection into privileged processes
- **Abuse Elevation Control Mechanism**: UAC bypass techniques

### Defense Evasion
- **Obfuscated Files or Information**: Encrypted payloads, packed executables
- **Impair Defenses**: Disabling security tools, clearing logs
- **Hide Artifacts**: Hidden files and directories

### Credential Access
- **OS Credential Dumping**: LSASS memory dumping, SAM database access
- **Steal or Forge Kerberos Tickets**: Kerberoasting, golden ticket attacks

### Discovery
- **System Owner/User Discovery**: whoami, net user commands
- **Network Service Scanning**: Port scanning, service enumeration
- **System Information Discovery**: System profiling, configuration enumeration

### Lateral Movement
- **Remote Services**: RDP, SSH, SMB
- **Use Alternate Authentication Material**: Pass the hash, pass the ticket

### Collection
- **Screen Capture**: Screenshot tools, screen recording
- **Data from Information Repositories**: Database queries, file system access

### Command and Control
- **Application Layer Protocol**: HTTP/HTTPS, DNS
- **Proxy**: SOCKS proxies, HTTP proxies
- **Encrypted Channel**: TLS, custom encryption

### Exfiltration
- **Exfiltration Over C2 Channel**: Data theft through C2 communication
- **Data Compressed**: Archive files, compressed data

### Impact
- **Data Encrypted for Impact**: Ransomware, data destruction
- **Service Stop**: Stopping critical services

## Malware Families

### Primary Malware
- **MEATBALL**: Custom backdoor for persistent access
- **BACKDRIFT**: RAT with advanced evasion capabilities
- **BOOMTRACE**: Reconnaissance and information gathering tool
- **RAWDOOR**: Backdoor with tunneling capabilities

### Tools
- **MIMIKATZ**: Credential dumping and privilege escalation
- **AceCryptor**: File encryption and obfuscation
- **GobRAT**: Remote access trojan

## Target Sectors

### Primary Targets
- **Maritime Industry**: Shipping companies, port authorities
- **Logistics**: Transportation, supply chain management
- **Government**: Maritime agencies, transportation departments

### Geographic Focus
- **Asia-Pacific**: Primary focus on regional maritime infrastructure
- **Global**: International shipping and logistics networks

## Indicators of Compromise (IOCs)

### Network Indicators
- **C2 Domains**: Suspicious domains associated with ST operations
- **IP Addresses**: Known ST infrastructure IP addresses
- **Ports**: Commonly used ports for C2 communication

### File Indicators
- **File Hashes**: SHA-256 hashes of ST malware samples
- **File Names**: Common file names used by ST tools
- **Registry Keys**: Registry entries created by ST malware

### Behavioral Indicators
- **Network Patterns**: Unusual network traffic patterns
- **Process Behavior**: Suspicious process creation and execution
- **File System Changes**: Unusual file creation and modification

## Detection Strategies

### Network Detection
```suricata
# MEATBALL C2 Communication
alert tcp any any -> any any (msg:"ST - MEATBALL C2 Communication"; content:"|4D 45 41 54 42 41 4C 4C|"; flow:established,to_server; sid:2025102001; rev:1;)

# BACKDRIFT DNS Tunneling
alert dns any any -> any 53 (msg:"ST - BACKDRIFT DNS Tunneling"; content:"|excessive subdomain length|"; sid:2025102004; rev:1;)
```

### Host Detection
```powershell
# DLL Sideloading Detection
Get-Process | Where-Object {$_.ProcessName -match "suspicious_process" -and $_.Modules.ModuleName -contains "suspicious_dll"}

# Service Creation Detection
Get-Service | Where-Object {$_.Name -match "suspicious_service" -and $_.Status -eq "Running"}
```

## Mitigation Strategies

### Prevention
- **Network Segmentation**: Isolate critical maritime systems
- **Access Controls**: Implement strict access controls
- **Security Awareness**: Train personnel on phishing and social engineering

### Detection
- **Endpoint Protection**: Deploy EDR solutions
- **Network Monitoring**: Monitor for suspicious network traffic
- **Log Analysis**: Regular analysis of security logs

### Response
- **Incident Response**: Have procedures for ST incidents
- **Forensic Analysis**: Preserve evidence for investigation
- **Recovery**: Use clean backups for system recovery

## Related Documentation

- [ST Hunt Report](../../Hunt_Playbooks/Active-Mission/Shotgun_Tiger/Hunt_Report.md)
- [ST Suricata Rules](../../Detections/Network/ST_Suricata_Rules.md)
- [ST Windows Host Detections](../../Detections/Host/Windows/ST_Windows_Host_Detections.md)

## References

- [CISA Alert - Chinese State-Sponsored Threats](https://www.cisa.gov/news-events/cybersecurity-advisories/)
- [MITRE ATT&CK - Shotgun Tiger](https://attack.mitre.org/groups/)
- [NCSC Guidance - Maritime Cybersecurity](https://www.ncsc.gov.uk/)
