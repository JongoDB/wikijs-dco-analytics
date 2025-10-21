---
title: All Techniques Index
type: reference
importable: true
exportable: true
last_reviewed: 2025-01-20
---

# All Techniques Index

This index aggregates technique mappings distilled from comprehensive threat intelligence analysis. Each entry links to MITRE ATT&CK and lists associated malware/tools, plus notes extracted from source analysis.

## Technique Mappings

| Technique | Associated Malware/Tools | Notes |
|-----------|-------------------------|-------|
| `T1001` | SO-HOBOT-NT | Data Obfuscation techniques |
| `T1003` | Comsvcs.dll, DUCKFAT, Diskshadow.exe, MIMIKATZ, PIVY, Poison Ivy, VersaMem, dsdbutil.exe, ntdsutil.exe, wbadmin.exe | OS Credential Dumping |
| `T1003.001` | LSASS, Mimikatz, Procdump | LSASS Memory credential dumping |
| `T1016` | Network configuration discovery | System Network Configuration Discovery |
| `T1018` | GobRAT, MeatBall | Remote System Discovery |
| `T1021` | GobRAT | Remote Services for lateral movement |
| `T1027` | AceCryptor, AppleJeus, BLINDINGCAN, Certutil.exe, MagicRat, MeatBall, PlugX, RAWDOOR, SOGU | Obfuscated Files or Information |
| `T1027.013` | File encryption, packing | Steganography techniques |
| `T1033` | BLINDINGCAN, SO-HOBOT-NT, ScanLine, TUONI, WHOAMI, whoami | System Owner/User Discovery |
| `T1036` | AppleJeus, BLINDINGCAN, GobRAT, MagicRat, RAWDOOR, VersaMem | Masquerading techniques |
| `T1041` | AppleJeus, BLINDINGCAN, DUCKFAT, RAWDOOR | Exfiltration Over C2 Channel |
| `T1046` | GobRAT, ScanLine | Network Service Scanning |
| `T1047` | Windows Management Instrumentation | WMI for execution |
| `T1048` | Cmd.exe, TestWindowRemoteAgent.exe | Exfiltration Over Alternative Protocol |
| `T1049` | Network monitoring tools | System Network Connections Discovery |
| `T1053` | AppleJeus, BLINDINGCAN, MagicRat, STOWAWAY, TUONI | Scheduled Task/Job |
| `T1053.004` | Cron jobs | Scheduled Task/Job: Cron |
| `T1053.005` | Windows Task Scheduler | Scheduled Task/Job: Scheduled Task |
| `T1055` | AceCryptor, FourteenHi, MeatBall, PlugX, SOGU, SPARROWDOOR, VersaMem | Process Injection |
| `T1055.001` | DLL injection | Process Injection: Dynamic-link Library Injection |
| `T1055.012` | Process hollowing | Process Injection: Process Hollowing |
| `T1056` | DUCKFAT, Gh0st RAT, PIVY, PlugX, Poison Ivy, SOGU, VersaMem | Input Capture |
| `T1056.004` | Credential capture | Input Capture: Credential API Hooking |
| `T1057` | Gh0st RAT, MeatBall, PlugX, SOGU | Process Discovery |
| `T1059` | BLINDINGCAN, Cmd.exe, DUCKFAT, FourteenHi, Gh0st RAT, GobRAT, MIMIKATZ, MagicRat, MeatBall, Mimikatz, PlugX, RAWDOOR, SOGU, STOWAWAY, TUONI | Command and Scripting Interpreter |
| `T1059.002` | Unix Shell | Command and Scripting Interpreter: Unix Shell |
| `T1059.003` | Windows Command Shell | Command and Scripting Interpreter: Windows Command Shell |
| `T1059.004` | Unix Shell | Command and Scripting Interpreter: Unix Shell |
| `T1070` | BLINDINGCAN, FourteenHi, MagicRat, MeatBall, PlugX, RAWDOOR, SOGU, Update.exe | Indicator Removal |
| `T1070.006` | Log clearing | Indicator Removal: Timestomp |
| `T1071` | AppleJeus, BLINDINGCAN, FourteenHi, Gh0st RAT, MagicRat, PlugX, RAWDOOR, SO-HOBOT-NT, SOGU, SPARROWDOOR, STOWAWAY, VersaMem | Application Layer Protocol |
| `T1071.001` | HTTP/HTTPS | Application Layer Protocol: Web Protocols |
| `T1071.004` | DNS | Application Layer Protocol: DNS |
| `T1078` | GobRAT, SO-HOBOT-NT | Valid Accounts |
| `T1082` | BLINDINGCAN, MeatBall, PlugX, SOGU | System Information Discovery |
| `T1083` | DUCKFAT, MeatBall, PlugX, RAWDOOR, SOGU | File and Directory Discovery |
| `T1090` | GobRAT, SO-HOBOT-NT, STOWAWAY | Proxy techniques |
| `T1102` | FourteenHi, RAWDOOR, TUONI | Web Service |
| `T1102.002` | Bidirectional communication | Web Service: Bidirectional Communication |
| `T1105` | AppInstaller.exe, AppleJeus, Bitsadmin.exe, Certutil.exe, DUCKFAT, FourteenHi, Gh0st RAT, GobRAT, Hh.exe, Installutil.exe, MagicRat, Msedge.exe, Mshta.exe, RAWDOOR, STOWAWAY, ScanLine, Update.exe | Ingress Tool Transfer |
| `T1113` | Gh0st RAT, MeatBall, PIVY, PlugX, Poison Ivy, SOGU | Screen Capture |
| `T1115` | Clipboard data access | Clipboard Data |
| `T1125` | Gh0st RAT | Video Capture |
| `T1127` | Trusted Developer Utilities | Trusted Developer Utilities Proxy Execution |
| `T1134` | SPARROWDOOR | Access Token Manipulation |
| `T1134.001` | Token impersonation | Access Token Manipulation: Token Impersonation/Theft |
| `T1136` | Account creation | Create Account |
| `T1190` | GobRAT, MagicRat, VersaMem | Exploit Public-Facing Application |
| `T1202` | Diskshadow.exe | Indirect Command Execution |
| `T1204.002` | Malicious file execution | User Execution: Malicious File |
| `T1218` | Bitsadmin.exe, Control.exe, Hh.exe, Installutil.exe, Mavinject.exe, Mmc.exe, Msconfig.exe, Msedge.exe, Mshta.exe, Msiexec.exe, Odbcconf.exe, Regasm.exe, Regsvcs.exe, Regsvr32.exe, Rundll32.exe, Update.exe, Verclsid.exe, Wmic.exe | Signed Binary Proxy Execution |
| `T1218.011` | Rundll32 execution | Signed Binary Proxy Execution: Rundll32 |
| `T1485` | Data destruction | Data Destruction |
| `T1486` | Ransomware encryption | Data Encrypted for Impact |
| `T1490` | System recovery inhibition | Inhibit System Recovery |
| `T1497` | AceCryptor | Virtualization/Sandbox Evasion |
| `T1505.003` | Web shell installation | Server Software Component: Web Shell |
| `T1543` | FourteenHi, Gh0st RAT, MeatBall, PIVY, PlugX, Poison Ivy, RAWDOOR, SOGU, SPARROWDOOR, TUONI | Create or Modify System Process |
| `T1543.003` | Windows service creation | Create or Modify System Process: Windows Service |
| `T1543.004` | Launchd service creation | Create or Modify System Process: Launchd |
| `T1547` | AppleJeus, BLINDINGCAN, GobRAT, MeatBall, PIVY, PlugX, Poison Ivy, SO-HOBOT-NT, SOGU, STOWAWAY, TUONI | Boot or Logon Autostart Execution |
| `T1547.001` | Registry run keys | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| `T1548` | Gh0st RAT, PIVY, PlugX, Poison Ivy, SOGU, SPARROWDOOR | Abuse Elevation Control Mechanism |
| `T1550` | Alternate authentication material | Use Alternate Authentication Material |
| `T1550.002` | Pass the hash | Use Alternate Authentication Material: Pass the Hash |
| `T1553` | AppleJeus | Subvert Trust Controls |
| `T1558` | MIMIKATZ | Steal or Forge Kerberos Tickets |
| `T1560` | Data archiving | Archive Collected Data |
| `T1562` | GobRAT, SO-HOBOT-NT, fltMC.exe | Impair Defenses |
| `T1564` | Bitsadmin.exe, Certutil.exe, Cmd.exe, Mavinject.exe, PlugX, RAWDOOR, Rundll32.exe, SOGU, Wmic.exe | Hide Artifacts |
| `T1564.001` | Hidden files and directories | Hide Artifacts: Hidden Files and Directories |
| `T1566` | AceCryptor, AppleJeus, BLINDINGCAN, PIVY, Poison Ivy | Phishing |
| `T1566.002` | Spearphishing links | Phishing: Spearphishing Link |
| `T1573` | AppleJeus, BLINDINGCAN, FourteenHi, Gh0st RAT, GobRAT, MeatBall, SPARROWDOOR, STOWAWAY | Encrypted Channel |
| `T1573.001` | Symmetric cryptography | Encrypted Channel: Symmetric Cryptography |
| `T1574` | AppleJeus, FourteenHi, MeatBall, PlugX, RAWDOOR, SOGU, SPARROWDOOR | Hijack Execution Flow |
| `T1574.002` | DLL sideloading | Hijack Execution Flow: DLL Side-Loading |
| `T1583` | Infrastructure acquisition | Acquire Infrastructure |
| `T1583.001` | Domain acquisition | Acquire Infrastructure: Domains |
| `T1583.006` | Web service acquisition | Acquire Infrastructure: Web Services |
| `T1587` | Capability development | Develop Capabilities |
| `T1587.001` | Malware development | Develop Capabilities: Malware |
| `T1588` | Capability acquisition | Obtain Capabilities |
| `T1588.003` | Code signing certificates | Obtain Capabilities: Code Signing Certificates |
| `T1588.004` | Digital certificates | Obtain Capabilities: Digital Certificates |

## Usage Notes

### Technique Categories
- **Initial Access**: T1190, T1566
- **Execution**: T1059, T1053, T1204
- **Persistence**: T1543, T1547, T1574
- **Privilege Escalation**: T1548, T1055, T1134
- **Defense Evasion**: T1027, T1070, T1562, T1564
- **Credential Access**: T1003, T1558, T1115
- **Discovery**: T1033, T1018, T1046, T1049, T1082, T1083, T1057
- **Lateral Movement**: T1021, T1550
- **Collection**: T1113, T1125, T1560
- **Command and Control**: T1071, T1090, T1573, T1102
- **Exfiltration**: T1041, T1048
- **Impact**: T1485, T1486, T1490

### Malware Family Mapping
- **AppleJeus**: T1027, T1033, T1041, T1053, T1059, T1071, T1204, T1543, T1547, T1548, T1564, T1566, T1573, T1583, T1587, T1588
- **SO-HOBOT-NT**: T1033, T1046, T1071, T1078, T1090, T1562
- **SparrowDoor**: T1003, T1055, T1071, T1090, T1115, T1134, T1547
- **VersaMem**: T1003, T1036, T1055, T1056, T1059, T1071, T1190, T1543, T1547
- **ScanLine**: T1033, T1046, T1059, T1071, T1547

## Related Documentation

- [Technique Cards](Technique_Cards.md)
- [Other References](Other_References.md)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## References

- MITRE ATT&CK Framework
- Threat Intelligence Reports
- Malware Analysis Reports
- Security Research Publications
