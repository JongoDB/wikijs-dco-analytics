---
title: Suricata Rules - Bazooka Tiger
type: network-detection
importable: true
exportable: true
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1016", "T1027.013", "T1033", "T1046", "T1049", "T1055.012", "T1056.004", "T1059.003", "T1071", "T1071.001", "T1071.004", "T1090", "T1115", "T1134.001", "T1136", "T1218.011", "T1505.003", "T1543.003", "T1547", "T1547.001", "T1574.002"]
---

# Suricata Rules - Bazooka Tiger

## Overview

This document contains Suricata network detection rules specifically designed to detect Bazooka Tiger (BT) threat actor activities. These rules focus on detecting network traffic patterns associated with BT's malware families including SO-HOBOT-NT, VersaMem, and SparrowDoor, as well as their associated tools.

## Network Detection Rules

### SO-HOBOT-NT Detection
```suricata
# SO-HOBOT-NT SOHO Router Botnet Communication
alert tcp any any -> any any (msg:"BT - SO-HOBOT-NT Router Botnet Communication"; content:"|suspicious_pattern|"; flow:established,to_server; sid:2025101001; rev:1;)

# SO-HOBOT-NT Network Scanning Activity
alert tcp $HOME_NET any -> $HOME_NET any (msg:"BT - Violation of Network Scanning"; threshold:type both,track by_src,count 50,seconds 60; sid:2025101002; rev:1;)
```

### VersaMem Detection
```suricata
# VersaMem Memory Dumping Activity
alert tcp any any -> any any (msg:"BT - VersaMem Memory Dumping"; content:"|LSASS|"; flow:established,to_server; sid:2025101003; rev:1;)

# VersaMem Credential Harvesting
alert tcp any any -> any any (msg:"BT - VersaMem Credential Harvesting"; content:"|SAM|"; flow:established,to_server; sid:2025101004; rev:1;)
```

### SparrowDoor Detection
```suricata
# SparrowDoor HTTPS C2 Communication
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"BT - SparrowDoor TLS C2 Possible"; tls.sni; content:"suspicious_domain"; sid:2025101005; rev:1;)

# SparrowDoor Service Installation
alert tcp any any -> any any (msg:"BT - SparrowDoor Service Installation"; content:"|SearchIndexer|"; flow:established,to_server; sid:2025101006; rev:1;)
```

### Tool Detection Rules

#### ScanLine Detection
```suricata
# ScanLine Port Scanning Activity
alert tcp $HOME_NET any -> $HOME_NET any (msg:"BT - ScanLine Port Scan Detected"; threshold:type both,track by_src,count 50,seconds 60; sid:2025101007; rev:1;)

# ScanLine High Volume Scanning
alert tcp any any -> any any (msg:"BT - High Volume Port Scanning"; threshold:type both,track by_src,count 100,seconds 30; sid:2025101008; rev:1;)
```

#### Stowaway Detection
```suricata
# Stowaway Proxy Communication
alert tcp any any -> any any (msg:"BT - Stowaway Proxy Communication"; content:"|stowaway|"; flow:established,to_server; sid:2025101009; rev:1;)

# Stowaway Tunneling Activity
alert tcp any any -> any any (msg:"BT - Stowaway Tunneling"; content:"|tunnel|"; flow:established,to_server; sid:2025101010; rev:1;)
```

#### TUONI Detection
```suricata
# TUONI Command Execution
alert tcp any any -> any any (msg:"BT - TUONI Command Execution"; content:"|tuoni|"; flow:established,to_server; sid:2025101011; rev:1;)

# TUONI Lateral Movement
alert tcp any any -> any any (msg:"BT - TUONI Lateral Movement"; content:"|lateral|"; flow:established,to_server; sid:2025101012; rev:1;)
```

#### Whoami Detection
```suricata
# Whoami Information Gathering
alert tcp any any -> any any (msg:"BT - Whoami Information Gathering"; content:"|whoami|"; flow:established,to_server; sid:2025101013; rev:1;)

# Whoami Process Discovery
alert tcp any any -> any any (msg:"BT - Whoami Process Discovery"; content:"|process|"; flow:established,to_server; sid:2025101014; rev:1;)
```

## General BT Detection Rules

### Network Anomaly Detection
```suricata
# BT Network Anomaly - Unusual Traffic Patterns
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"BT - Unusual Outbound Traffic"; threshold:type both,track by_src,count 10,seconds 60; sid:2025101015; rev:1;)

# BT DNS Tunneling Detection
alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BT - Potential DNS Tunneling"; dns_query; content:"excessive_subdomain_length"; sid:2025101016; rev:1;)
```

### Protocol-Specific Detection
```suricata
# BT SMB Abuse Detection
alert smb any any -> any any (msg:"BT - SMB Abuse Detected"; content:"|SMB abuse|"; sid:2025101017; rev:1;)

# BT HTTP C2 Communication
alert http any any -> any any (msg:"BT - HTTP C2 Communication"; http_uri; content:"/c2"; sid:2025101018; rev:1;)
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
threshold gen_id 1, sig_id 2025101007, type both, track by_src, count 50, seconds 60
threshold gen_id 1, sig_id 2025101008, type both, track by_src, count 100, seconds 30
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

- [BT Windows Host Detections](../Host/Windows/Barker_Windows_Host_Detections.md)
- [BT Hunt Report](../../Hunt_Playbooks/Active-Mission/Bazooka_Tiger/Hunt_Report.md)
- [BT Generic Reference](../../Reference/BT_Generic_Reference.md)
