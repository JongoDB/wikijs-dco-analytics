---
title: Suricata Rules - Shotgun Tiger
type: network-detection
importable: true
exportable: true
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1041", "T1049", "T1059", "T1059.003", "T1071", "T1071.001", "T1071.004", "T1090", "T1547", "T1560"]
---

# Suricata Rules - Shotgun Tiger

## Overview

This document contains Suricata network detection rules specifically designed to detect Shotgun Tiger (ST) threat actor activities. These rules focus on detecting network traffic patterns associated with ST's malware families and tools, including MEATBALL, BACKDRIFT, and various reconnaissance tools.

## Network Detection Rules

### MEATBALL Detection
```suricata
# MEATBALL C2 Communication
alert tcp any any -> any any (msg:"ST - MEATBALL C2 Communication"; content:"|4D 45 41 54 42 41 4C 4C|"; flow:established,to_server; content:"|MEATBALL|"; sid:2025102001; rev:1;)

# MEATBALL Backdoor Communication
alert tcp any any -> any any (msg:"ST - MEATBALL Backdoor Communication"; content:"|backdoor|"; flow:established,to_server; sid:2025102002; rev:1;)
```

### BACKDRIFT Detection
```suricata
# BACKDRIFT C2 Communication
alert tcp any any -> any any (msg:"ST - BACKDRIFT C2 Communication"; content:"|42 41 43 4B 44 52 49 46 54|"; flow:established,to_server; content:"|BACKDRIFT|"; sid:2025102003; rev:1;)

# BACKDRIFT DNS Tunneling
alert dns any any -> any 53 (msg:"ST - BACKDRIFT DNS Tunneling"; content:"|excessive subdomain length|"; sid:2025102004; rev:1;)
```

### DLL Sideloading Detection
```suricata
# DLL Sideloading Activity
alert file any any -> any any (msg:"ST - Potential DLL Sideloading"; file_ext:"dll"; content:"|MZ|"; depth:2; sid:2025102005; rev:1;)

# Suspicious DLL Loading
alert tcp any any -> any any (msg:"ST - Suspicious DLL Loading"; content:"|LoadLibrary|"; flow:established,to_server; sid:2025102006; rev:1;)
```

### PowerShell Abuse Detection
```suricata
# PowerShell C2 Communication
alert tcp any any -> any any (msg:"ST - PowerShell C2 Communication"; content:"powershell.exe"; flow:established,to_server; sid:2025102007; rev:1;)

# PowerShell Encoded Commands
alert tcp any any -> any any (msg:"ST - PowerShell Encoded Commands"; content:"|EncodedCommand|"; flow:established,to_server; sid:2025102008; rev:1;)
```

### Maritime/Logistics Targeting Detection
```suricata
# Maritime/Logistics Targeting
alert ip any any -> any any (msg:"ST - Potential Maritime/Logistics Targeting"; content:"port"; sid:2025102009; rev:1;)

# Access Broker File Transfer
alert ip any any -> any any (msg:"ST - Access Broker File Transfer"; content:"|GET /|"; http_method; sid:2025102010; rev:1;)
```

## General ST Detection Rules

### Network Reconnaissance
```suricata
# ST Network Reconnaissance
alert tcp $HOME_NET any -> $HOME_NET any (msg:"ST - Network Reconnaissance Activity"; threshold:type both,track by_src,count 30,seconds 60; sid:2025102011; rev:1;)

# ST Port Scanning
alert tcp any any -> any any (msg:"ST - Port Scanning Activity"; threshold:type both,track by_src,count 20,seconds 30; sid:2025102012; rev:1;)
```

### Command and Control Communication
```suricata
# ST C2 Communication Patterns
alert tcp any any -> any any (msg:"ST - C2 Communication Pattern"; content:"|C2|"; flow:established,to_server; sid:2025102013; rev:1;)

# ST HTTPS C2
alert tls any any -> any any (msg:"ST - HTTPS C2 Communication"; tls.sni; content:"suspicious_domain"; sid:2025102014; rev:1;)
```

### Data Exfiltration
```suricata
# ST Data Exfiltration
alert tcp any any -> any any (msg:"ST - Potential Data Exfiltration"; threshold:type both,track by_src,count 5,seconds 60; sid:2025102015; rev:1;)

# ST File Transfer
alert http any any -> any any (msg:"ST - Suspicious File Transfer"; http_uri; content:"/upload"; sid:2025102016; rev:1;)
```

## Tool-Specific Detection

### Reconnaissance Tools
```suricata
# ST Reconnaissance Tool Usage
alert tcp any any -> any any (msg:"ST - Reconnaissance Tool Usage"; content:"|recon|"; flow:established,to_server; sid:2025102017; rev:1;)

# ST Information Gathering
alert tcp any any -> any any (msg:"ST - Information Gathering"; content:"|info|"; flow:established,to_server; sid:2025102018; rev:1;)
```

### Persistence Mechanisms
```suricata
# ST Persistence Attempt
alert tcp any any -> any any (msg:"ST - Persistence Attempt"; content:"|persist|"; flow:established,to_server; sid:2025102019; rev:1;)

# ST Service Installation
alert tcp any any -> any any (msg:"ST - Service Installation"; content:"|service|"; flow:established,to_server; sid:2025102020; rev:1;)
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
threshold gen_id 1, sig_id 2025102011, type both, track by_src, count 30, seconds 60
threshold gen_id 1, sig_id 2025102012, type both, track by_src, count 20, seconds 30
threshold gen_id 1, sig_id 2025102015, type both, track by_src, count 5, seconds 60
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

- [ST Windows Host Detections](../Host/Windows/ST_Windows_Host_Detections.md)
- [ST Hunt Report](../../Hunt_Playbooks/Active-Mission/Shotgun_Tiger/Hunt_Report.md)
- [ST Threat Intelligence](../../Threat_Intelligence/Actors/Shotgun_Tiger.md)
