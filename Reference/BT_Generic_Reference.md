---
title: BT Generic Reference
type: reference
importable: false
exportable: false
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1016", "T1033", "T1049", "T1053.005", "T1059.003", "T1071", "T1071.001", "T1071.004", "T1547"]
---

# BT Generic Reference

## Overview

This document provides a comprehensive reference for Bazooka Tiger (BT) threat actor activities, including tools, techniques, and procedures (TTPs) observed in their campaigns. Bazooka Tiger is a sophisticated threat actor group with demonstrated capabilities in espionage, financial theft, and disruption operations.

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
- **SO-HOBOT-NT**: SOHO router botnet malware
- **SparrowDoor**: Backdoor with persistence capabilities
- **VersaMem**: Memory-resident malware for Versa Director exploitation

### Tools and Utilities
- **ScanLine**: Port scanning and reconnaissance tool
- **Stowaway**: Multi-hop proxy tool for network pivoting
- **Whoami**: System discovery utility (abused)
- **TUONI**: Command and control framework

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
# BT Network Anomaly Detection
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"BT - Unusual Outbound Traffic"; threshold:type both,track by_src,count 10,seconds 60; sid:2025104014; rev:1;)

# BT SMB Abuse Detection
alert smb any any -> any any (msg:"BT - SMB Abuse Detected"; content:"|SMB abuse|"; sid:2025104015; rev:1;)
```

### Host Detection
```powershell
# BT Process Creation Monitoring
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4688 -and 
    $_.Properties[1].Value -like "*suspicious_process*"
} | Select-Object TimeCreated, ProcessName, CommandLine

# BT Credential Access Detection
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4662 -and 
    $_.Properties[6].Value -like "*lsass*"
} | Select-Object TimeCreated, ProcessName, CommandLine
```

## Hunting Queries

### Splunk Searches
```splunk
# BT Suspicious Process Creation
index=wineventlog* EventCode=4688 (NewProcessName="*suspicious*" OR CommandLine="*bt_related*")
| stats count by host, user, NewProcessName, CommandLine

# BT Credential Access Attempts
index=wineventlog* (EventCode=4662 OR EventCode=4688) (ObjectName="*lsass*" OR ProcessName="*mimikatz*")
| stats count by host, user, ObjectName, ProcessName
```

### KQL Queries
```kql
// BT Process Creation Detection
DeviceProcessEvents
| where ProcessCommandLine contains "suspicious" or FileName contains "bt_related"
| project Timestamp, DeviceName, FileName, ProcessCommandLine

// BT Network Anomaly Detection
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
- **Incident Response**: Have procedures for BT-related incidents
- **Forensic Analysis**: Preserve evidence for investigation
- **System Recovery**: Use clean backups for system recovery
- **Credential Rotation**: Rotate potentially compromised credentials

## Related Documentation

- [BT Suricata Rules](../Detections/Network/BT_Suricata_Rules.md)
- [BT Windows Host Detections](../Detections/Host/Windows/Barker_Windows_Host_Detections.md)
- [BT Hunt Report](../Hunt_Playbooks/Active-Mission/Bazooka_Tiger/Hunt_Report.md)

## References

- [CISA Alert - Chinese State-Sponsored Threats](https://www.cisa.gov/news-events/cybersecurity-advisories/)
- [MITRE ATT&CK - Bazooka Tiger](https://attack.mitre.org/groups/)
- [FBI Guidance - Chinese Cyber Threats](https://www.fbi.gov/)
