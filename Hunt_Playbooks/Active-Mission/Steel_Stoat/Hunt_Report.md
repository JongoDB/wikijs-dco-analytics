---
title: Steel Stoat - Hunt Report
type: hunt-report
importable: true
exportable: true
last_reviewed: 2025-01-20
mitre_ids: ["T1001.003", "T1003", "T1018", "T1033", "T1036.005", "T1041", "T1046", "T1049", "T1053.005", "T1057", "T1059.003", "T1071", "T1071.001", "T1071.004", "T1090", "T1105", "T1218.011", "T1497.003", "T1547", "T1560", "T1562.004", "T1573"]
---

# Steel Stoat - Hunt Report

## Overview

This hunt report provides comprehensive information about Steel Stoat (SS) threat actor activities, including malware families, tools, techniques, and procedures (TTPs) observed in their campaigns. Steel Stoat is a sophisticated threat actor group with demonstrated capabilities in espionage, financial theft, and disruption operations.

## Executive Summary

Steel Stoat has been observed conducting sophisticated cyber operations targeting various sectors including defense, financial services, and critical infrastructure. Their operations span multiple phases from initial access through persistence and data exfiltration.

## Entities Covered

### Malware Families
- **AppleJeus**: Trojanized cryptocurrency trading applications
- **AuditCred**: Loader/backdoor DLL used in bank heists
- **BADCALL**: Proxy malware for relay nodes
- **BLINDINGCAN**: Full-featured RAT used in "Dream Job" campaigns
- **DRATzarus**: Stealthy RAT with anti-analysis capabilities
- **MagicRat**: Qt-based RAT deployed via server exploitation
- **RATANKBA**: Remote access trojan for persistent access
- **WannaCry**: Self-propagating ransomware worm
- **Clop**: Ransomware with data exfiltration capabilities

### Tools and Utilities
- **Impacket**: Network protocol tool for lateral movement
- **Scanbox**: Web profiling framework
- **Various RATs**: Multiple remote access trojans for different purposes

## Related Detections

### Network Detections
- [SS Suricata Rules](../../Detections/Network/SS_Suricata_Rules.md)
- [SS Network Anomaly Detection](../../Detections/Network/SS_Suricata_Rules.md)

### Host Detections
- [SS Windows Host Detections](../../Detections/Host/Windows/SS_Windows_Host_Detections.md)
- [SS Process Monitoring](../../Detections/Host/Windows/SS_Windows_Host_Detections.md)

### Threat Intelligence
- [SS Threat Intelligence](../../Threat_Intelligence/Actors/Steel_Stoat.md)
- [SS Actor Profile](../../Threat_Intelligence/Actors/Steel_Stoat.md)

## Hunting Playbook Snippets

### Network Hunting
```suricata
# SS Network Anomaly Detection
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SS - Unusual Outbound Traffic"; threshold:type both,track by_src,count 10,seconds 60; sid:2025104020; rev:1;)

# SS SMB Abuse Detection
alert smb any any -> any any (msg:"SS - SMB Abuse Detected"; content:"|SMB abuse|"; sid:2025104021; rev:1;)
```

### Host Hunting
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

### Splunk Hunting
```splunk
# SS Suspicious Process Creation
index=wineventlog* EventCode=4688 (NewProcessName="*suspicious*" OR CommandLine="*ss_related*")
| stats count by host, user, NewProcessName, CommandLine

# SS Credential Access Attempts
index=wineventlog* (EventCode=4662 OR EventCode=4688) (ObjectName="*lsass*" OR ProcessName="*mimikatz*")
| stats count by host, user, ObjectName, ProcessName
```

### KQL Hunting
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
- **Incident Response**: Have procedures for SS-related incidents
- **Forensic Analysis**: Preserve evidence for investigation
- **System Recovery**: Use clean backups for system recovery
- **Credential Rotation**: Rotate potentially compromised credentials

## Related Documentation

- [SS Suricata Rules](../../Detections/Network/SS_Suricata_Rules.md)
- [SS Windows Host Detections](../../Detections/Host/Windows/SS_Windows_Host_Detections.md)
- [SS Threat Intelligence](../../Threat_Intelligence/Actors/Steel_Stoat.md)
- [SS Generic Reference](../../Reference/SS_Generic_Reference.md)

## References

- [CISA Alert - North Korean State-Sponsored Threats](https://www.cisa.gov/news-events/cybersecurity-advisories/)
- [MITRE ATT&CK - Steel Stoat](https://attack.mitre.org/groups/)
- [FBI Guidance - North Korean Cyber Threats](https://www.fbi.gov/)
