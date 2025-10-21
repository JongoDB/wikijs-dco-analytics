---
title: Suricata Rules - Steel Stoat
type: network-detection
importable: true
exportable: true
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1018", "T1041", "T1046", "T1049", "T1059.003", "T1071", "T1071.001", "T1071.004", "T1090", "T1547", "T1560", "T1562.004", "T1573"]
---

# Suricata Rules - Steel Stoat

## Overview

This document contains Suricata network detection rules specifically designed to detect Steel Stoat (SS) threat actor activities. These rules focus on detecting network traffic patterns associated with SS's malware families and tools, including RATANKBA, WannaCry, Clop, and various reconnaissance tools.

## Network Detection Rules

### RATANKBA Detection
```suricata
# RATANKBA C2 Communication
alert tcp any any -> any any (msg:"SS - RATANKBA C2 Communication"; content:"|52 41 54 41 4E 4B 42 41|"; flow:established,to_server; sid:2025103001; rev:1;)

# RATANKBA Backdoor Communication
alert tcp any any -> any any (msg:"SS - RATANKBA Backdoor Communication"; content:"|backdoor|"; flow:established,to_server; sid:2025103002; rev:1;)
```

### WannaCry Detection
```suricata
# WannaCry SMB Exploit Attempt
alert ip any any -> any any (msg:"SS - WannaCry SMB Exploit Attempt"; content:"|FF|SMB"; depth:1; flow:established,to_server; sid:2025103003; rev:1;)

# WannaCry Ransomware Activity
alert smb any any -> any any (msg:"SS - WannaCry Ransomware Activity"; content:"|SMBv1 exploit attempt|"; sid:2025103004; rev:1;)
```

### Clop Ransomware Detection
```suricata
# Clop Ransomware File Extension
alert ip any any -> any any (msg:"SS - Clop Ransomware File Extension Change"; content:".clop"; file_extension; sid:2025103005; rev:1;)

# Clop Ransomware Activity
alert smb any any -> any any (msg:"SS - Clop Ransomware Activity"; content:"|SMB encryption attempt|"; sid:2025103006; rev:1;)
```

### Impacket Detection
```suricata
# Impacket SMB Activity
alert tcp any any -> any 445 (msg:"SS - Impacket SMB Activity"; flow:established,to_server; content:"|00 00 00 00|"; depth:4; sid:2025103007; rev:1;)

# Impacket SMB Exploitation
alert smb any any -> any any (msg:"SS - Impacket SMB Exploitation"; content:"|NTLM authentication attempt|"; sid:2025103008; rev:1;)
```

### Tomcat Backdoor Detection
```suricata
# Tomcat Backdoor HTTP Request
alert http any any -> any 8080 (msg:"SS - Tomcat Backdoor HTTP Request"; http_uri; content:"/manager/html"; sid:2025103009; rev:1;)

# Tomcat Manager Upload
alert http any any -> any any (msg:"SS - Tomcat Manager Upload"; http_method; content:"POST"; http_uri; content:"/manager/html/upload"; sid:2025103010; rev:1;)
```

### Scanbox Detection
```suricata
# Scanbox Web Profiling
alert http any any -> any any (msg:"SS - Scanbox Web Profiling"; http_user_agent; content:"Scanbox"; sid:2025103011; rev:1;)

# Scanbox Suspicious User Agent
alert http any any -> any any (msg:"SS - Scanbox Suspicious User Agent"; http_user_agent; content:"Mozilla/4.0"; sid:2025103012; rev:1;)
```

### DarkManila Detection
```suricata
# DarkManila Activity
alert ip any any -> any any (msg:"SS - Potential DarkManila Activity"; content:"|D8 4F 52 4D|"; sid:2025103013; rev:1;)

# DarkManila C2 Communication
alert tcp any any -> any any (msg:"SS - DarkManila C2 Communication"; content:"|darkmanila|"; flow:established,to_server; sid:2025103014; rev:1;)
```

## General SS Detection Rules

### Network Anomaly Detection
```suricata
# SS Network Anomaly - Unusual Traffic Patterns
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SS - Unusual Outbound Traffic"; threshold:type both,track by_src,count 10,seconds 60; sid:2025103015; rev:1;)

# SS DNS Tunneling Detection
alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"SS - Potential DNS Tunneling"; dns_query; content:"excessive_subdomain_length"; sid:2025103016; rev:1;)
```

### Protocol-Specific Detection
```suricata
# SS SMB Abuse Detection
alert smb any any -> any any (msg:"SS - SMB Abuse Detected"; content:"|SMB abuse|"; sid:2025103017; rev:1;)

# SS HTTP C2 Communication
alert http any any -> any any (msg:"SS - HTTP C2 Communication"; http_uri; content:"/c2"; sid:2025103018; rev:1;)
```

### Command and Control Detection
```suricata
# SS C2 Communication Patterns
alert tcp any any -> any any (msg:"SS - C2 Communication Pattern"; content:"|C2|"; flow:established,to_server; sid:2025103019; rev:1;)

# SS HTTPS C2
alert tls any any -> any any (msg:"SS - HTTPS C2 Communication"; tls.sni; content:"suspicious_domain"; sid:2025103020; rev:1;)
```

### Data Exfiltration Detection
```suricata
# SS Data Exfiltration
alert tcp any any -> any any (msg:"SS - Potential Data Exfiltration"; threshold:type both,track by_src,count 5,seconds 60; sid:2025103021; rev:1;)

# SS File Transfer
alert http any any -> any any (msg:"SS - Suspicious File Transfer"; http_uri; content:"/upload"; sid:2025103022; rev:1;)
```

## Rule Configuration

### Variables
```suricata
# Define HOME_NET and EXTERNAL_NET in your suricata.yaml
HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
EXTERNAL_NET: "!$HOME_NET"
```

### Threshold Configuration
```suricata
# Configure thresholds in threshold.conf
threshold gen_id 1, sig_id 2025103015, type both, track by_src, count 10, seconds 60
threshold gen_id 1, sig_id 2025103016, type both, track by_src, count 5, seconds 60
threshold gen_id 1, sig_id 2025103021, type both, track by_src, count 5, seconds 60
```

## Usage Instructions

1. **Import Rules**: Copy the rules to your Suricata rules directory
2. **Configure Variables**: Update HOME_NET and EXTERNAL_NET in suricata.yaml
3. **Test Rules**: Validate rules using suricata -T
4. **Deploy**: Restart Suricata to load new rules
5. **Monitor**: Review alerts and tune thresholds as needed

## Maintenance

- **Regular Updates**: Review and update rules based on new threat intelligence
- **Threshold Tuning**: Adjust thresholds based on network environment
- **False Positive Management**: Monitor for false positives and adjust rules accordingly
- **Performance Monitoring**: Monitor Suricata performance impact

## Related Documentation

- [SS Windows Host Detections](../Host/Windows/SS_Windows_Host_Detections.md)
- [SS Hunt Report](../../Hunt_Playbooks/Active-Mission/Steel_Stoat/Hunt_Report.md)
- [SS Threat Intelligence](../../Threat_Intelligence/Actors/Steel_Stoat.md)

## References

- [CISA Alert - North Korean State-Sponsored Threats](https://www.cisa.gov/news-events/cybersecurity-advisories/)
- [MITRE ATT&CK - Steel Stoat](https://attack.mitre.org/groups/)
- [FBI Guidance - North Korean Cyber Threats](https://www.fbi.gov/)
