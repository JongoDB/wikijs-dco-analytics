---
title: Bazooka Tiger - Hunt Report
type: hunt-report
importable: true
exportable: true
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1016", "T1027.013", "T1033", "T1046", "T1049", "T1055.012", "T1056.004", "T1059.003", "T1071", "T1071.001", "T1071.004", "T1090", "T1115", "T1134.001", "T1136", "T1218.011", "T1505.003", "T1543.003", "T1547", "T1547.001", "T1574.002"]
---

# Bazooka Tiger — Hunt Report

## Executive Summary

Bazooka Tiger (BT) is a sophisticated threat actor group known for targeting critical infrastructure and government organizations. This hunt report provides comprehensive guidance for detecting and mitigating BT activities, focusing on their primary malware families and tools.

### Key Findings
- **Primary Malware**: SO-HOBOT-NT, VersaMem, SparrowDoor
- **Key Tools**: ScanLine, Stowaway, TUONI, whoami
- **Target Sectors**: Critical infrastructure, government, defense
- **Attack Vectors**: SOHO router compromise, lateral movement, credential theft

## Threat Actor Profile

### Attribution
- **Group Name**: Bazooka Tiger (BT)
- **Country of Origin**: China
- **Motivation**: Espionage, intellectual property theft
- **Target Sectors**: Critical infrastructure, government, defense contractors

### Tactics, Techniques, and Procedures (TTPs)
- **Initial Access**: SOHO router compromise, supply chain attacks
- **Persistence**: Service installation, registry modifications
- **Credential Access**: Memory dumping, credential harvesting
- **Lateral Movement**: Network scanning, service exploitation
- **Command and Control**: HTTPS communication, DNS tunneling

## Entities Covered

### Infrastructure/Malware
- **SO-HOBOT-NT**: SOHO router botnet infrastructure
- **VersaMem**: Memory dumping and credential theft tool
- **SparrowDoor**: Custom backdoor for persistent access

### Tools/Utilities
- **ScanLine**: Port scanning and network reconnaissance
- **Stowaway**: Network tunneling and proxy capabilities
- **TUONI**: Command execution and lateral movement
- **whoami**: Information gathering and system enumeration

## Hunting Methodology

### Phase 1: Initial Reconnaissance
1. **Network Scanning Detection**
   - Monitor for high-volume port scanning activities
   - Look for ScanLine usage patterns
   - Identify unusual network traffic patterns

2. **SOHO Router Monitoring**
   - Monitor for SO-HOBOT-NT botnet activities
   - Check for router configuration changes
   - Identify suspicious network infrastructure

### Phase 2: Lateral Movement
1. **Credential Theft Detection**
   - Monitor for VersaMem memory dumping activities
   - Look for LSASS access attempts
   - Identify credential harvesting patterns

2. **Service Exploitation**
   - Monitor for service installation attempts
   - Check for suspicious service creation
   - Identify lateral movement through services

### Phase 3: Persistence
1. **Backdoor Installation**
   - Monitor for SparrowDoor installation
   - Check for suspicious service creation
   - Identify persistence mechanisms

2. **Registry Modifications**
   - Monitor for registry changes
   - Check for persistence entries
   - Identify suspicious registry modifications

## Hunting Queries

### Splunk Searches
```splunk
# SO-HOBOT-NT Detection
index=network* (src_ip=* OR dest_ip=*) (port=23 OR port=80 OR port=443 OR port=8080)
| stats count by src_ip, dest_ip, port, protocol
| where count > 100

# VersaMem Detection
index=wineventlog* (EventCode=4656 OR EventCode=4663) (ObjectName="*SAM*" OR ObjectName="*LSASS*")
| stats count by host, user, ObjectName, ProcessName

# SparrowDoor Detection
index=wineventlog* (ServiceName="SearchIndexer" OR ProcessName="SearchIndexer.exe")
| stats count by host, user, ServiceName, ProcessName, ImagePath
```

### KQL Queries
```kql
// ScanLine Detection
DeviceProcessEvents
| where ProcessCommandLine contains "scanline" or ProcessCommandLine contains "-p "
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// TUONI Detection
DeviceProcessEvents
| where ProcessCommandLine contains "tuoni" or ProcessCommandLine contains "lateral"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Detection Rules

### Network Detection
```suricata
# SO-HOBOT-NT Detection
alert tcp any any -> any any (msg:"BT - SO-HOBOT-NT Router Botnet Communication"; content:"|suspicious_pattern|"; flow:established,to_server; sid:2025101001; rev:1;)

# ScanLine Detection
alert tcp $HOME_NET any -> $HOME_NET any (msg:"BT - ScanLine Port Scan Detected"; threshold:type both,track by_src,count 50,seconds 60; sid:2025101002; rev:1;)
```

### Host Detection
```powershell
# VersaMem Detection
Get-Process | Where-Object {$_.ProcessName -match "versamem" -or $_.CommandLine -match "memory"}

# SparrowDoor Detection
Get-Service -Name "SearchIndexer" | Where-Object {$_.Path -like "*ProgramData\Microsoft\DRM\*"}
```

## Mitigation Strategies

### Prevention
1. **Network Segmentation**
   - Implement strict network segmentation
   - Isolate critical systems from internet access
   - Use network access controls

2. **Credential Protection**
   - Implement Credential Guard
   - Use Local Administrator Password Solution (LAPS)
   - Enable LSASS protection

3. **SOHO Router Security**
   - Keep router firmware updated
   - Implement strong authentication
   - Monitor router configurations

### Detection
1. **Endpoint Protection**
   - Deploy EDR solutions
   - Enable behavioral detection
   - Monitor for suspicious activities

2. **Network Monitoring**
   - Deploy network monitoring solutions
   - Monitor for port scanning activities
   - Check for unusual traffic patterns

### Response
1. **Incident Response**
   - Have procedures for BT incidents
   - Isolate compromised systems
   - Preserve evidence for investigation

2. **Recovery**
   - Use clean backups for recovery
   - Implement system hardening
   - Monitor for re-infection

## IOCs (Indicators of Compromise)

### File Hashes
- **ScanLine**: 3a97d9b6f17754dcd38ca7fc89caab04
- **SparrowDoor Loader**: e0b107be8034976f6e91cfcc2bbc792b49ea61a071166968fec775af28b1f19c

### Registry Keys
- `HKLM\SYSTEM\CurrentControlSet\Services\SearchIndexer`

### Network Indicators
- **Ports**: 23, 80, 443, 8080
- **Protocols**: SMB, HTTPS, DNS

## Related Documentation

- [BT Suricata Rules](../../Detections/Network/BT_Suricata_Rules.md)
- [BT Windows Host Detections](../../Detections/Host/Windows/BT_Windows_Host_Detections.md)
- [BT Generic Reference](../../Reference/BT_Generic_Reference.md)

## References

- [CISA Alert - Volt Typhoon](https://www.cisa.gov/news-events/cybersecurity-advisories/)
- [MITRE ATT&CK - Bazooka Tiger](https://attack.mitre.org/groups/G0134/)
- [NCSC Guidance - Chinese State-Sponsored Threats](https://www.ncsc.gov.uk/)
