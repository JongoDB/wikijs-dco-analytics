---
title: Windows Host Detections - Shotgun Tiger
type: host-detection
importable: true
exportable: true
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1016", "T1033", "T1047", "T1049", "T1053.005", "T1055.001", "T1059.003", "T1071", "T1071.001", "T1071.004", "T1090", "T1218.011", "T1543.003", "T1547"]
---

# Windows Host Detections - Shotgun Tiger

## Overview

This document contains Windows host-based detection rules and queries specifically designed to detect Shotgun Tiger (ST) threat actor activities. These detections focus on identifying suspicious process creation, credential access, lateral movement, and persistence activities associated with maritime and logistics targeting.

## Detection Categories

### Process Creation Monitoring

#### Suspicious Process Creation
```powershell
# PowerShell suspicious execution detection
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4688 -and 
    ($_.Properties[1].Value -like "*powershell*" -or $_.Properties[1].Value -like "*cmd.exe*")
} | Select-Object TimeCreated, Id, LevelDisplayName, Message

# Process creation with suspicious parent processes
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4688 -and 
    $_.Properties[5].Value -in @('cmd.exe', 'powershell.exe') -and
    $_.Properties[8].Value -like "*suspicious_pattern*"
}
```

#### Built-in Windows Commands Abuse
```powershell
# Detection of legitimate tools used maliciously
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4688 -and 
    $_.Properties[8].Value -match "(certutil\.exe|wmic|bitsadmin|schtasks\.exe)"
}
```

### Credential Access Detection

#### LSASS Process Access
```powershell
# LSASS access monitoring
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4662 -and 
    $_.Properties[6].Value -like "*lsass*"
}

# Process creation targeting credential stores
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4688 -and 
    ($_.Properties[8].Value -like "*mimikatz*" -or 
     $_.Properties[8].Value -like "*procdump*" -or
     $_.Properties[8].Value -like "*lsass*")
}
```

### Lateral Movement Detection

#### Service Installation and Modification
```powershell
# Service creation/modification detection
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 7045 -and 
    $_.Properties[6].Value -notlike "*system*"
}

# Scheduled task creation
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4698 -and 
    $_.Properties[1].Value -notlike "*system*"
}
```

## High-Value Windows Event IDs

### Critical Event IDs for Detection

| Event ID | Description | Use Case |
|----------|-------------|----------|
| 4688 | Process Creation | Monitor for suspicious executables and parent-child relationships |
| 4662 | LSASS Process Access | Detect credential dumping attempts |
| 4624 | Successful Logon | Track authentication events |
| 4663 | File Access | Monitor access to sensitive files |
| 4768 | Kerberos Authentication | Detect ticket manipulation |
| 7045 | Service Installation | Monitor service creation |

### Sysmon Event IDs

| Event ID | Description | Detection Focus |
|----------|-------------|-----------------|
| 1 | Process Creation | Non-standard locations, suspicious parent-child relationships |
| 3 | Network Connection | C2 IPs, unusual external connections |
| 8 | CreateRemoteThread | Code injection detection |
| 17/18 | Pipe Events | Lateral movement via named pipes |

## Hunting Queries

### Splunk Searches
```splunk
# Suspicious process creation
index=wineventlog* EventCode=4688 (NewProcessName="*powershell*" OR NewProcessName="*cmd.exe*")
| stats count by host, user, NewProcessName, CommandLine

# LSASS access attempts
index=wineventlog* (EventCode=4662 OR EventCode=4688) (ObjectName="*lsass*" OR ProcessName="*mimikatz*")
| stats count by host, user, ObjectName, ProcessName

# Service installation
index=wineventlog* EventCode=7045
| stats count by host, user, ServiceName, ImagePath
```

### KQL Queries
```kql
// Process creation with suspicious patterns
DeviceProcessEvents
| where ProcessCommandLine contains "powershell" or ProcessCommandLine contains "cmd.exe"
| where ProcessCommandLine contains "certutil" or ProcessCommandLine contains "wmic"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// LSASS access detection
DeviceProcessEvents
| where ProcessCommandLine contains "lsass" or ProcessCommandLine contains "mimikatz"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Detection Rules

### PowerShell Execution Detection
```powershell
# PowerShell encoded command detection
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {
    $_.Id -eq 4104 -and 
    $_.Properties[2].Value -like "*EncodedCommand*"
}
```

### Credential Dumping Detection
```powershell
# Multiple credential dumping indicators
Get-WinEvent -LogName Security | Where-Object {
    ($_.ID -eq 4688 -and $_.Properties[8].Value -match "(mimikatz|procdump|lsass)") -or
    ($_.ID -eq 4662 -and $_.Properties[6].Value -like "*sam*") -or
    ($_.ID -eq 4663 -and $_.Properties[6].Value -like "*ntds*")
}
```

## Mitigation Strategies

### Prevention
- **Credential Protection**: Implement Credential Guard and LAPS
- **Process Monitoring**: Deploy EDR solutions with behavioral detection
- **Service Control**: Implement service control policies
- **Network Segmentation**: Isolate critical systems

### Detection
- **Event Logging**: Ensure comprehensive Windows event logging
- **Sysmon Deployment**: Deploy Sysmon for enhanced process monitoring
- **SIEM Integration**: Integrate with SIEM for correlation
- **Real-time Monitoring**: Set up real-time alerting

### Response
- **Incident Response**: Have procedures for credential compromise
- **Forensic Analysis**: Preserve evidence for investigation
- **System Recovery**: Use clean backups for recovery

## Configuration Requirements

### Windows Event Logging
```powershell
# Enable required audit policies
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Process Tracking" /success:enable /failure:enable
```

### Sysmon Configuration
- **Process Creation**: Monitor all process creation events
- **Network Connections**: Log all network connections
- **File Creation**: Monitor file creation in sensitive locations
- **Registry Monitoring**: Track registry modifications

## Related Documentation

- [ST Suricata Rules](../Network/ST_Suricata_Rules.md)
- [ST Hunt Report](../../Hunt_Playbooks/Active-Mission/Shotgun_Tiger/Hunt_Report.md)
- [ST Threat Intelligence](../../Threat_Intelligence/Actors/Shotgun_Tiger.md)

## References

- [MITRE ATT&CK - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [Microsoft Security Blog - Credential Protection](https://www.microsoft.com/security/blog/)
- [CISA Alert - Chinese State-Sponsored Threats](https://www.cisa.gov/news-events/cybersecurity-advisories/)
