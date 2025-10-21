---
title: SS Generic Reference
type: reference
importable: false
exportable: false
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1018", "T1041", "T1046", "T1049", "T1059.003", "T1071", "T1071.001", "T1071.004", "T1090", "T1547", "T1560", "T1562.004", "T1573"]
---

# SS Generic Reference

## Overview

This document provides a comprehensive reference for Steel Stoat (SS) threat actor activities, including tools, techniques, and procedures (TTPs) observed in their campaigns. Steel Stoat is a sophisticated threat actor group with demonstrated capabilities in espionage, financial theft, and disruption operations.

## Threat Actor Profile

### Primary Objectives
- **Espionage**: Information gathering and strategic advantage
- **Financial Theft**: Targeting financial institutions and cryptocurrency exchanges
- **Disruption**: Infrastructure disruption and system compromise

### Targeted Sectors
- Aerospace & Defense
- Government entities
- Telecommunications
- Manufacturing
- Finance
- Consulting
- Legal Services

## Initial Access Methods

### Spear Phishing
- **Web Bugs**: Leveraging web bugs for target profiling
- **Scanbox Framework**: Using Scanbox web-profiling framework for intelligence gathering
- **Social Engineering**: Sophisticated social engineering campaigns

### Exploitation Techniques
- **Publicly Known Exploits**: Utilizing widely available exploits for initial and lateral movement
- **Zero-Day Exploits**: Development and deployment of custom exploits
- **DLL Sideloading**: Exploiting legitimate applications to load malicious code

## Malware Families

### Remote Access Trojans (RATs)
- **RATANKBA**: Remote access trojan for persistent access
- **BLINDINGCAN**: Remote access trojan with C2 capabilities
- **MagicRat**: Remote access trojan with extensive capabilities
- **DRATzarus**: Remote access trojan with anti-debug features

### Tools and Utilities
- **Impacket**: Network protocol tool for lateral movement
- **Scanbox**: Web profiling framework
- **Various RATs**: Multiple remote access trojans for different purposes

## Persistence Mechanisms

### Registry-Based Persistence
- **Run Keys**: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- **RunOnce Keys**: HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
- **Service Registration**: Creating Windows services for persistence

### Scheduled Tasks
- **Task Creation**: Using schtasks.exe for persistence
- **Elevated Privileges**: Running tasks with elevated privileges
- **Hidden Execution**: Tasks configured for hidden execution

## Lateral Movement Techniques

### Credential Harvesting
- **LSASS Dumping**: Targeting LSASS process for credential extraction
- **SAM Database**: Accessing SAM database for local credentials
- **NTDS.dit**: Targeting Active Directory database

### Network Protocols
- **SMB/RPC**: Using SMB and RPC for lateral movement
- **WMI**: Windows Management Instrumentation for remote execution
- **PowerShell**: PowerShell remoting and execution

## Detection Strategies

### Network Detection
```suricata
# SS Network Anomaly Detection
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SS - Unusual Outbound Traffic"; threshold:type both,track by_src,count 10,seconds 60; sid:2025104018; rev:1;)

# SS SMB Abuse Detection
alert smb any any -> any any (msg:"SS - SMB Abuse Detected"; content:"|SMB abuse|"; sid:2025104019; rev:1;)
```

### Host Detection
```powershell
# SS Process Creation Monitoring
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4688 -and 
    $_.Properties[1].Value -like "*suspicious_process*"
} | Select-Object TimeCreated, ProcessName, CommandLine

# SS Credential Access Detection
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4662 -and 
    $_.Properties[6].Value -like "*lsass*"
} | Select-Object TimeCreated, ProcessName, CommandLine
```

## Hunting Queries

### Splunk Searches
```splunk
# SS Suspicious Process Creation
index=wineventlog* EventCode=4688 (NewProcessName="*suspicious*" OR CommandLine="*ss_related*")
| stats count by host, user, NewProcessName, CommandLine

# SS Credential Access Attempts
index=wineventlog* (EventCode=4662 OR EventCode=4688) (ObjectName="*lsass*" OR ProcessName="*mimikatz*")
| stats count by host, user, ObjectName, ProcessName
```

### KQL Queries
```kql
// SS Process Creation Detection
DeviceProcessEvents
| where ProcessCommandLine contains "suspicious" or FileName contains "ss_related"
| project Timestamp, DeviceName, FileName, ProcessCommandLine

// SS Network Anomaly Detection
DeviceNetworkEvents
| where RemotePort == 445 or RemotePort == 135
| project Timestamp, DeviceName, RemoteUrl, RemotePort, InitiatingProcessFileName
```

## Mitigation Strategies

### Prevention
- **Endpoint Protection**: Deploy EDR solutions with behavioral detection
- **Network Segmentation**: Implement network segmentation and access controls
- **Patch Management**: Keep systems updated with latest security patches
- **User Training**: Educate users about phishing and social engineering

### Detection
- **Event Logging**: Ensure comprehensive Windows event logging
- **Network Monitoring**: Monitor for suspicious network connections
- **Process Monitoring**: Monitor for suspicious process creation and execution
- **Credential Protection**: Implement credential protection mechanisms

### Response
- **Incident Response**: Have procedures for SS-related incidents
- **Forensic Analysis**: Preserve evidence for investigation
- **System Recovery**: Use clean backups for system recovery
- **Credential Rotation**: Rotate potentially compromised credentials

## Related Documentation

- [SS Suricata Rules](../Detections/Network/SS_Suricata_Rules.md)
- [SS Windows Host Detections](../Detections/Host/Windows/SS_Windows_Host_Detections.md)
- [SS Hunt Report](../Hunt_Playbooks/Active-Mission/Steel_Stoat/Hunt_Report.md)

## References

- [CISA Alert - North Korean State-Sponsored Threats](https://www.cisa.gov/news-events/cybersecurity-advisories/)
- [MITRE ATT&CK - Steel Stoat](https://attack.mitre.org/groups/)
- [FBI Guidance - North Korean Cyber Threats](https://www.fbi.gov/)
