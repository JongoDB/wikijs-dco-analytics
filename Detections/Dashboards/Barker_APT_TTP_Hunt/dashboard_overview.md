---
title: Barker APT TTP Hunt Dashboard Overview
type: dashboard
importable: true
exportable: true
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1021", "T1059", "T1071", "T1078", "T1083", "T1115"]
---

# Barker APT TTP Hunt Dashboard Overview

## Overview

The Barker APT TTP Hunt Dashboard is a comprehensive Splunk Dashboard Studio visualization designed to detect and analyze Advanced Persistent Threat (APT) activities across host and network telemetry. This dashboard focuses on identifying Tactics, Techniques, and Procedures (TTPs) commonly used by threat actors such as Bazooka Tiger, Shotgun Tiger, and Steel Stoat.

## Dashboard Components

### Overview Section
- **Impacket Service Exec**: Detects service execution patterns consistent with Impacket tools
- **PowerShell EncodedCommand**: Identifies PowerShell encoded command execution
- **Shadow Copy Deletion**: Detects shadow copy deletion attempts
- **Tomcat Manager Upload**: Identifies suspicious Tomcat manager uploads
- **Gh0st RAT C2 Traffic**: Detects Gh0st RAT command and control traffic
- **Suspicious Network Connections**: Identifies high-volume network connections

### Credential Access Section
- **Credential Dumping Activities**: Detects potential credential dumping activities targeting SAM, LSASS, and other credential stores

### Lateral Movement Section
- **Lateral Movement Activities**: Identifies potential lateral movement activities through logon analysis

## Key Features

### Real-time Monitoring
- **Live Data**: Real-time monitoring of APT activities across the network
- **Alert Integration**: Integration with Splunk alerting for immediate notification
- **Customizable Time Ranges**: Flexible time range selection for historical analysis

### Cross-Surface Correlation
- **Host-Network Correlation**: Correlates host and network telemetry for comprehensive threat detection
- **Multi-Source Analysis**: Analyzes data from Windows Event Logs, Suricata, and other security tools
- **Behavioral Analysis**: Identifies behavioral patterns indicative of APT activities

### Threat Actor Focus
- **Bazooka Tiger**: Detection of BT-specific TTPs and malware families
- **Shotgun Tiger**: Identification of ST activities and tools
- **Steel Stoat**: Detection of SS-related threats and techniques

## Usage Instructions

### Dashboard Access
1. **Import Dashboard**: Import the `apt_ttp_hunt_dashboard.json` into Splunk Dashboard Studio
2. **Configure Data Sources**: Ensure proper index configuration for Windows Event Logs and Suricata
3. **Set Time Range**: Select appropriate time range for analysis
4. **Apply Filters**: Use host filters to focus on specific systems or network segments

### Analysis Workflow
1. **Review Overview**: Start with the overview section to identify potential threats
2. **Investigate Alerts**: Drill down into specific alerts for detailed analysis
3. **Correlate Events**: Use cross-surface correlation to understand attack progression
4. **Document Findings**: Document findings for incident response and threat hunting

## Configuration Requirements

### Data Sources
- **Windows Event Logs**: Index containing Windows security events
- **Suricata Logs**: Index containing network security monitoring data
- **Additional Logs**: Any additional security tool logs for enhanced correlation

### Index Configuration
```splunk
# Windows Event Log Index
wineventlog*

# Suricata Index
suricata*

# Additional security indexes
security*
```

### User Permissions
- **Dashboard Access**: Users need access to Splunk Dashboard Studio
- **Data Access**: Users need access to security-related indexes
- **Alert Permissions**: Users need permissions to create and manage alerts

## Maintenance

### Regular Updates
- **Rule Updates**: Update detection rules based on new threat intelligence
- **Dashboard Updates**: Enhance dashboard based on user feedback and new requirements
- **Data Source Updates**: Add new data sources as they become available

### Performance Optimization
- **Index Optimization**: Optimize indexes for better performance
- **Query Optimization**: Optimize queries for faster response times
- **Resource Monitoring**: Monitor dashboard performance and resource usage

## Related Documentation

- [KPI Breakdown](kpi_breakdown.md)
- [References](references.md)
- [APT TTP Hunt Dashboard JSON](../apt_ttp_hunt_dashboard.json)

## Support

For questions or issues with the dashboard, please contact the DCO Analytics Team or refer to the Splunk Dashboard Studio documentation.
