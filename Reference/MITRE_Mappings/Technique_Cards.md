---
title: MITRE ATT&CK Technique Cards
type: reference
importable: false
exportable: false
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1016", "T1033", "T1049", "T1059.003", "T1071", "T1071.001", "T1071.004", "T1547"]
---

# MITRE ATT&CK Technique Cards

## Overview

This document provides detailed technique cards for MITRE ATT&CK techniques relevant to the threat actors and malware families covered in this repository. Each technique card includes a description, examples, detection methods, and mitigation strategies.

## Technique Cards

### T1003 - OS Credential Dumping

#### Description
Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software.

#### Examples
- **LSASS Memory**: Dumping credentials from LSASS process memory
- **SAM Database**: Accessing local SAM database for credentials
- **NTDS.dit**: Targeting Active Directory database
- **Security Account Manager**: Accessing security account manager

#### Detection Methods
```powershell
# LSASS Access Detection
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4662 -and 
    $_.Properties[6].Value -like "*lsass*"
} | Select-Object TimeCreated, ProcessName, CommandLine

# SAM Database Access
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4663 -and 
    $_.Properties[6].Value -like "*sam*"
} | Select-Object TimeCreated, ProcessName, CommandLine
```

#### Mitigation Strategies
- **Credential Guard**: Enable Windows Credential Guard
- **LSA Protection**: Enable LSA Protection
- **Privileged Access Management**: Implement privileged access management
- **Monitoring**: Monitor for credential dumping attempts

### T1016 - System Network Configuration Discovery

#### Description
Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information gathering of remote systems.

#### Examples
- **ipconfig**: Using ipconfig to gather network information
- **ifconfig**: Using ifconfig on Linux systems
- **netstat**: Using netstat to view network connections
- **arp**: Using arp to view ARP table

#### Detection Methods
```powershell
# Network Discovery Commands
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4688 -and 
    $_.Properties[8].Value -match "(ipconfig|netstat|arp)"
} | Select-Object TimeCreated, ProcessName, CommandLine
```

#### Mitigation Strategies
- **Network Segmentation**: Implement network segmentation
- **Access Controls**: Implement strict access controls
- **Monitoring**: Monitor for network discovery activities
- **User Training**: Educate users about suspicious activities

### T1033 - System Owner/User Discovery

#### Description
Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly use a system, or whether a user is actively using the system.

#### Examples
- **whoami**: Using whoami to identify current user
- **who**: Using who to identify logged in users
- **w**: Using w to identify active users
- **quser**: Using quser to query user sessions

#### Detection Methods
```powershell
# User Discovery Commands
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4688 -and 
    $_.Properties[8].Value -match "(whoami|who|quser)"
} | Select-Object TimeCreated, ProcessName, CommandLine
```

#### Mitigation Strategies
- **Access Controls**: Implement strict access controls
- **Monitoring**: Monitor for user discovery activities
- **User Training**: Educate users about suspicious activities
- **Incident Response**: Have procedures for suspicious activities

### T1049 - System Network Connections Discovery

#### Description
Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.

#### Examples
- **netstat**: Using netstat to view network connections
- **ss**: Using ss to view network connections on Linux
- **lsof**: Using lsof to view network connections
- **netstat -an**: Using netstat with specific flags

#### Detection Methods
```powershell
# Network Connection Discovery
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4688 -and 
    $_.Properties[8].Value -match "netstat"
} | Select-Object TimeCreated, ProcessName, CommandLine
```

#### Mitigation Strategies
- **Network Monitoring**: Implement network monitoring
- **Access Controls**: Implement strict access controls
- **Monitoring**: Monitor for network discovery activities
- **User Training**: Educate users about suspicious activities

### T1059.003 - Command and Scripting Interpreter: Windows Command Shell

#### Description
Adversaries may abuse the Windows command shell for execution. The Windows command shell (cmd) is the primary command prompt on Windows systems.

#### Examples
- **cmd.exe**: Using cmd.exe for command execution
- **cmd /c**: Using cmd with specific commands
- **cmd /k**: Using cmd with keep-alive option
- **Command Line Arguments**: Using specific command line arguments

#### Detection Methods
```powershell
# Command Shell Execution
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4688 -and 
    $_.Properties[1].Value -like "*cmd.exe*"
} | Select-Object TimeCreated, ProcessName, CommandLine
```

#### Mitigation Strategies
- **Application Control**: Implement application control policies
- **Script Blocking**: Block malicious scripts
- **Monitoring**: Monitor for command shell execution
- **User Training**: Educate users about suspicious activities

### T1071 - Application Layer Protocol

#### Description
Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.

#### Examples
- **HTTP/HTTPS**: Using HTTP and HTTPS for communication
- **DNS**: Using DNS for communication
- **SMTP**: Using SMTP for communication
- **FTP**: Using FTP for communication

#### Detection Methods
```suricata
# HTTP/HTTPS Communication
alert http any any -> any any (msg:"Suspicious HTTP Communication"; flow:established,to_server; sid:2025104024; rev:1;)

# DNS Communication
alert dns any any -> any 53 (msg:"Suspicious DNS Communication"; dns_query; content:"suspicious_domain"; sid:2025104025; rev:1;)
```

#### Mitigation Strategies
- **Network Monitoring**: Implement network monitoring
- **Protocol Filtering**: Filter suspicious protocols
- **Traffic Analysis**: Analyze network traffic patterns
- **User Training**: Educate users about suspicious activities

### T1071.001 - Application Layer Protocol: Web Protocols

#### Description
Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.

#### Examples
- **HTTP**: Using HTTP for communication
- **HTTPS**: Using HTTPS for communication
- **WebSockets**: Using WebSockets for communication
- **REST APIs**: Using REST APIs for communication

#### Detection Methods
```suricata
# Web Protocol Communication
alert http any any -> any any (msg:"Suspicious Web Protocol Communication"; flow:established,to_server; sid:2025104026; rev:1;)
```

#### Mitigation Strategies
- **Web Filtering**: Implement web filtering
- **SSL Inspection**: Inspect SSL/TLS traffic
- **Traffic Analysis**: Analyze web traffic patterns
- **User Training**: Educate users about suspicious activities

### T1071.004 - Application Layer Protocol: DNS

#### Description
Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic.

#### Examples
- **DNS Queries**: Using DNS queries for communication
- **DNS Tunneling**: Using DNS for tunneling data
- **DNS Exfiltration**: Using DNS for data exfiltration
- **DNS C2**: Using DNS for command and control

#### Detection Methods
```suricata
# DNS Communication
alert dns any any -> any 53 (msg:"Suspicious DNS Communication"; dns_query; content:"suspicious_domain"; sid:2025104027; rev:1;)
```

#### Mitigation Strategies
- **DNS Filtering**: Implement DNS filtering
- **DNS Monitoring**: Monitor DNS traffic
- **Traffic Analysis**: Analyze DNS traffic patterns
- **User Training**: Educate users about suspicious activities

### T1547 - Boot or Logon Autostart Execution

#### Description
Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on a system.

#### Examples
- **Registry Run Keys**: Using registry run keys for persistence
- **Scheduled Tasks**: Using scheduled tasks for persistence
- **Startup Folders**: Using startup folders for persistence
- **Service Installation**: Installing services for persistence

#### Detection Methods
```powershell
# Registry Run Keys
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 13 -and 
    $_.Properties[5].Value -like "*Run*"
} | Select-Object TimeCreated, ProcessName, CommandLine

# Scheduled Tasks
Get-WinEvent -LogName Security | Where-Object {
    $_.ID -eq 4698
} | Select-Object TimeCreated, ProcessName, CommandLine
```

#### Mitigation Strategies
- **Application Control**: Implement application control policies
- **Registry Monitoring**: Monitor registry changes
- **Service Control**: Control service installation
- **User Training**: Educate users about suspicious activities

## Related Documentation

- [All Techniques Index](All_Techniques_Index.md)
- [Other References](Other_References.md)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls/)
