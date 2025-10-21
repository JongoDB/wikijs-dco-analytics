---
title: Bazooka Tiger
type: actor
importable: true
exportable: true
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1016", "T1027.013", "T1033", "T1046", "T1049", "T1055.012", "T1056.004", "T1059.003", "T1071", "T1071.001", "T1071.004", "T1090", "T1115", "T1134.001", "T1136", "T1218.011", "T1505.003", "T1543.003", "T1547", "T1547.001", "T1574.002"]
---

# Bazooka Tiger

## Overview

Bazooka Tiger (BT) is a sophisticated threat actor group known for targeting critical infrastructure and government organizations. The group employs a diverse toolkit of custom malware and publicly available tools to conduct espionage, financial theft, and disruption operations with a focus on SOHO router compromise and lateral movement techniques.

## Attribution

### Group Profile
- **Group Name**: Bazooka Tiger (BT)
- **Country of Origin**: China
- **Motivation**: Espionage, intellectual property theft, financial gain
- **Target Sectors**: Critical infrastructure, government, defense contractors, telecommunications
- **Active Since**: 2018

### Threat Level
- **Sophistication**: Very High
- **Resources**: State-sponsored
- **Persistence**: Long-term operations
- **Stealth**: Advanced evasion techniques

## Tactics, Techniques, and Procedures (TTPs)

### Initial Access
- **SOHO Router Compromise**: Targeting small office/home office routers
- **Supply Chain Attacks**: Compromising software supply chains
- **Spearphishing**: Web bugs and Scanbox framework for intelligence gathering
- **Exploit Public-Facing Application**: Zero-day exploits and publicly known vulnerabilities

### Execution
- **Command and Scripting Interpreter**: PowerShell, Windows Command Shell
- **Scheduled Task/Job**: Cron jobs, scheduled tasks
- **Process Injection**: DLL injection, process hollowing
- **User Execution**: Malicious file execution

### Persistence
- **Boot or Logon Autostart Execution**: Registry run keys, startup folders
- **Create or Modify System Process**: Windows services, launchd
- **Hijack Execution Flow**: DLL sideloading, executable hijacking
- **Server Software Component**: Web shells and backdoors

### Privilege Escalation
- **Process Injection**: DLL injection into privileged processes
- **Abuse Elevation Control Mechanism**: UAC bypass techniques

### Defense Evasion
- **Obfuscated Files or Information**: Encrypted payloads, packed executables
- **Hide Artifacts**: Hidden files and directories
- **Impair Defenses**: Disabling security tools, clearing logs
- **Masquerading**: Legitimate application impersonation

### Credential Access
- **OS Credential Dumping**: LSASS memory dumping, SAM database access
- **Input Capture**: Keylogging and credential harvesting
- **Steal or Forge Kerberos Tickets**: Kerberoasting, golden ticket attacks

### Discovery
- **System Owner/User Discovery**: whoami, net user commands
- **Network Service Scanning**: Port scanning, service enumeration
- **System Information Discovery**: System profiling, configuration enumeration
- **Network Service Discovery**: Network topology mapping

### Lateral Movement
- **Remote Services**: RDP, SSH, SMB
- **Use Alternate Authentication Material**: Pass the hash, pass the ticket
- **Network Scanning**: Port scanning and service exploitation

### Collection
- **Screen Capture**: Screenshot tools, screen recording
- **Data from Information Repositories**: Database queries, file system access
- **Clipboard Data**: Clipboard monitoring and data collection

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
- **SO-HOBOT-NT**: SOHO router botnet infrastructure for persistent access
- **VersaMem**: Memory-resident malware for Versa Director exploitation
- **SparrowDoor**: Custom backdoor for persistent access and stealth operations

### Tools
- **ScanLine**: Port scanning and network reconnaissance tool
- **Stowaway**: Multi-hop proxy tool for network pivoting
- **TUONI**: Command and control framework for lateral movement
- **whoami**: System discovery utility (abused for reconnaissance)

## Target Sectors

### Primary Targets
- **Critical Infrastructure**: Power grids, water systems, telecommunications
- **Government**: Government agencies, defense contractors
- **Aerospace & Defense**: Defense contractors, aerospace companies
- **Telecommunications**: Telecom providers, network infrastructure

### Geographic Focus
- **United States**: Primary focus on U.S. critical infrastructure
- **Global**: International targets for espionage and financial gain
- **Asia-Pacific**: Regional focus for strategic intelligence

## Indicators of Compromise (IOCs)

### Network Indicators
- **C2 Domains**: Suspicious domains associated with BT operations
- **IP Addresses**: Known BT infrastructure IP addresses
- **Ports**: 23, 80, 443, 8080 (SOHO router compromise)

### File Indicators
- **File Hashes**: 
  - ScanLine: 3a97d9b6f17754dcd38ca7fc89caab04
  - SparrowDoor Loader: e0b107be8034976f6e91cfcc2bbc792b49ea61a071166968fec775af28b1f19c
- **File Names**: Common file names used by BT tools
- **Registry Keys**: 
  - `HKLM\SYSTEM\CurrentControlSet\Services\SearchIndexer`

### Behavioral Indicators
- **Network Patterns**: Unusual network traffic patterns from SOHO routers
- **Process Behavior**: Suspicious process creation and execution
- **File System Changes**: Unusual file creation and modification

## Detection Strategies

### Network Detection
```suricata
# SO-HOBOT-NT Router Botnet Communication
alert tcp any any -> any any (msg:"BT - SO-HOBOT-NT Router Botnet Communication"; content:"|suspicious_pattern|"; flow:established,to_server; sid:2025101001; rev:1;)

# VersaMem Memory Dumping Activity
alert tcp any any -> any any (msg:"BT - VersaMem Memory Dumping"; content:"|LSASS|"; flow:established,to_server; sid:2025101003; rev:1;)

# SparrowDoor HTTPS C2 Communication
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"BT - SparrowDoor TLS C2 Possible"; tls.sni; content:"suspicious_domain"; sid:2025101005; rev:1;)

# ScanLine Port Scanning
alert tcp $HOME_NET any -> $HOME_NET any (msg:"BT - ScanLine Port Scan Detected"; threshold:type both,track by_src,count 50,seconds 60; sid:2025101002; rev:1;)
```

### Host Detection
```powershell
# VersaMem Detection
Get-Process | Where-Object {$_.ProcessName -match "versamem" -or $_.CommandLine -match "memory"}

# SparrowDoor Detection
Get-Service -Name "SearchIndexer" | Where-Object {$_.Path -like "*ProgramData\Microsoft\DRM\*"}

# SO-HOBOT-NT Registry Detection
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SearchIndexer" -ErrorAction SilentlyContinue
```

## Mitigation Strategies

### Prevention
- **Network Segmentation**: Isolate critical infrastructure systems
- **SOHO Router Security**: Keep router firmware updated, implement strong authentication
- **Access Controls**: Implement strict access controls and credential protection
- **Security Awareness**: Train personnel on phishing and social engineering

### Detection
- **Endpoint Protection**: Deploy EDR solutions with behavioral detection
- **Network Monitoring**: Monitor for suspicious network traffic and SOHO router activities
- **Log Analysis**: Regular analysis of security logs and network anomalies
- **Credential Protection**: Implement Credential Guard and LSASS protection

### Response
- **Incident Response**: Have procedures for BT incidents
- **Forensic Analysis**: Preserve evidence for investigation
- **Recovery**: Use clean backups for system recovery
- **Credential Rotation**: Rotate potentially compromised credentials

## Related Documentation

- [BT Hunt Report](../../Hunt_Playbooks/Active-Mission/Bazooka_Tiger/Hunt_Report.md)
- [BT Suricata Rules](../../Detections/Network/BT_Suricata_Rules.md)
- [BT Windows Host Detections](../../Detections/Host/Windows/BT_Windows_Host_Detections.md)
- [BT Generic Reference](../../Reference/BT_Generic_Reference.md)

## References

- [CISA Alert - Volt Typhoon](https://www.cisa.gov/news-events/cybersecurity-advisories/)
- [MITRE ATT&CK - Bazooka Tiger](https://attack.mitre.org/groups/G0134/)
- [NCSC Guidance - Chinese State-Sponsored Threats](https://www.ncsc.gov.uk/)
- [FBI Guidance - Chinese Cyber Threats](https://www.fbi.gov/)
