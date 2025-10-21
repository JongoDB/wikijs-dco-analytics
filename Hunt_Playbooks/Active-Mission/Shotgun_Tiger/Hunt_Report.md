---
title: Shotgun Tiger - Hunt Report
type: hunt-report
importable: true
exportable: true
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1003.006", "T1016", "T1033", "T1041", "T1047", "T1049", "T1053.005", "T1055.001", "T1059", "T1059.003", "T1070.006", "T1071", "T1071.001", "T1071.004", "T1090", "T1102.002", "T1218.011", "T1543.003", "T1547", "T1550", "T1560"]
---

# Shotgun Tiger - Hunt Report

## Overview

This hunt report provides comprehensive information about Shotgun Tiger (ST) threat actor activities, including malware families, tools, techniques, and procedures (TTPs) observed in their campaigns. Shotgun Tiger is a sophisticated threat actor group with demonstrated capabilities in espionage, financial theft, and disruption operations.

## Executive Summary

Shotgun Tiger has been observed conducting sophisticated cyber operations targeting various sectors including maritime, logistics, and critical infrastructure. Their operations span multiple phases from initial access through persistence and data exfiltration.

## Entities Covered

### Malware Families
- **BOOMTRACE**: Emerging threat with limited public information
- **RAWDOOR**: Malware with specific behavioral patterns
- **MIMIKATZ**: Credential dumping tool widely used by threat actors
- **AceCryptor**: Malware packer/crypter used to obfuscate payloads
- **GobRAT**: Remote access trojan targeting Linux systems

### Tools and Utilities
- **MIMIKATZ**: Credential harvesting and dumping tool
- **Various RATs**: Multiple remote access trojans for different purposes
- **Packing Tools**: Tools used to obfuscate and protect malware

## Related Detections

### Network Detections
- [ST Suricata Rules](../../../Detections/Network/ST_Suricata_Rules.md)
- [ST Network Anomaly Detection](../../../Detections/Network/ST_Suricata_Rules.md)

### Host Detections
- [ST Windows Host Detections](../../../Detections/Host/Windows/ST_Windows_Host_Detections.md)
- [ST Process Monitoring](../../../Detections/Host/Windows/ST_Windows_Host_Detections.md)

### Threat Intelligence
- [ST Threat Intelligence](../../../Threat_Intelligence/Actors/Shotgun_Tiger.md)
- [ST Actor Profile](../../../Threat_Intelligence/Actors/Shotgun_Tiger.md)

## Hunting Playbook Snippets

### Network Hunting
```suricata
# ST Network Anomaly Detection
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ST - Unusual Outbound Traffic"; threshold:type both,track by_src,count 10,seconds 60; sid:2025104022; rev:1;)

# ST SMB Abuse Detection
alert smb any any -> any any (msg:"ST - SMB Abuse Detected"; content:"|SMB abuse|"; sid:2025104023; rev:1;)
```

### Host Hunting
```powershell
# ST Process Creation Monitoring
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4688 -and 
    $_.Properties[1].Value -like "*suspicious_process*"
} | Select-Object TimeCreated, ProcessName, CommandLine

# ST Credential Access Detection
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4662 -and 
    $_.Properties[6].Value -like "*lsass*"
} | Select-Object TimeCreated, ProcessName, CommandLine
```

### Splunk Hunting
```splunk
# ST Suspicious Process Creation
index=wineventlog* EventCode=4688 (NewProcessName="*suspicious*" OR CommandLine="*st_related*")
| stats count by host, user, NewProcessName, CommandLine

# ST Credential Access Attempts
index=wineventlog* (EventCode=4662 OR EventCode=4688) (ObjectName="*lsass*" OR ProcessName="*mimikatz*")
| stats count by host, user, ObjectName, ProcessName
```

### KQL Hunting
```kql
// ST Process Creation Detection
DeviceProcessEvents
| where ProcessCommandLine contains "suspicious" or FileName contains "st_related"
| project Timestamp, DeviceName, FileName, ProcessCommandLine

// ST Network Anomaly Detection
DeviceNetworkEvents
| where RemotePort == 445 or RemotePort == 135
| project Timestamp, DeviceName, RemoteUrl, RemotePort, InitiatingProcessFileName
```

## Mitigations & Hardening

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
- **Incident Response**: Have procedures for ST-related incidents
- **Forensic Analysis**: Preserve evidence for investigation
- **System Recovery**: Use clean backups for system recovery
- **Credential Rotation**: Rotate potentially compromised credentials

## Related Documentation

- [ST Suricata Rules](../../../Detections/Network/ST_Suricata_Rules.md)
- [ST Windows Host Detections](../../../Detections/Host/Windows/ST_Windows_Host_Detections.md)
- [ST Threat Intelligence](../../../Threat_Intelligence/Actors/Shotgun_Tiger.md)
- [ST Generic Reference](../../../Reference/SS_Generic_Reference.md)

## References

- [CISA Alert - Chinese State-Sponsored Threats](https://www.cisa.gov/news-events/cybersecurity-advisories/)
- [MITRE ATT&CK - Shotgun Tiger](https://attack.mitre.org/groups/)
- [FBI Guidance - Chinese Cyber Threats](https://www.fbi.gov/)
