---
title: KPI Breakdown - Barker APT TTP Hunt Dashboard
type: dashboard-documentation
importable: false
exportable: false
last_reviewed: 2025-01-20
mitre_ids: ["T1003", "T1016", "T1033", "T1049", "T1059.003", "T1071", "T1071.001", "T1071.004", "T1547"]
---

# KPI Breakdown - Barker APT TTP Hunt Dashboard

## Overview

This document provides a detailed breakdown of the Key Performance Indicators (KPIs) and metrics used in the Barker APT TTP Hunt Dashboard. These KPIs are designed to measure the effectiveness of threat hunting activities and detection capabilities.

## Dashboard KPIs

### Threat Detection Metrics

#### Detection Coverage
- **Network Detection Coverage**: Percentage of network traffic monitored for APT activities
- **Host Detection Coverage**: Percentage of endpoints monitored for APT activities
- **Log Source Coverage**: Percentage of relevant log sources integrated into the dashboard

#### Detection Effectiveness
- **True Positive Rate**: Percentage of alerts that are confirmed as actual threats
- **False Positive Rate**: Percentage of alerts that are false positives
- **Detection Time**: Average time from threat activity to detection
- **Alert Response Time**: Average time from detection to response initiation

### Threat Hunting Metrics

#### Hunting Activity
- **Hunting Queries Executed**: Number of hunting queries run per time period
- **Hunting Coverage**: Percentage of MITRE ATT&CK techniques covered by hunting queries
- **Hunting Frequency**: Frequency of hunting activities across different techniques

#### Hunting Results
- **Threats Discovered**: Number of threats discovered through hunting activities
- **Threats Confirmed**: Number of threats confirmed as actual compromises
- **Threats Mitigated**: Number of threats successfully mitigated

### Operational Metrics

#### System Performance
- **Dashboard Load Time**: Time required to load dashboard visualizations
- **Query Performance**: Average time for dashboard queries to execute
- **Data Freshness**: Time lag between data collection and dashboard display

#### User Engagement
- **Dashboard Usage**: Frequency of dashboard access by analysts
- **Query Execution**: Number of custom queries executed by users
- **Alert Investigation**: Number of alerts investigated through the dashboard

## KPI Targets

### Detection Targets
- **Network Detection Coverage**: ≥ 95%
- **Host Detection Coverage**: ≥ 90%
- **True Positive Rate**: ≥ 85%
- **False Positive Rate**: ≤ 15%
- **Detection Time**: ≤ 5 minutes

### Hunting Targets
- **Hunting Coverage**: ≥ 80% of relevant MITRE ATT&CK techniques
- **Hunting Frequency**: Daily hunting activities for high-priority techniques
- **Threat Discovery Rate**: ≥ 5 threats discovered per month

### Operational Targets
- **Dashboard Load Time**: ≤ 10 seconds
- **Query Performance**: ≤ 30 seconds for complex queries
- **Data Freshness**: ≤ 5 minutes

## KPI Calculation Methods

### Detection Coverage Calculation
```
Detection Coverage = (Monitored Assets / Total Assets) × 100
```

### True Positive Rate Calculation
```
True Positive Rate = (Confirmed Threats / Total Alerts) × 100
```

### False Positive Rate Calculation
```
False Positive Rate = (False Positives / Total Alerts) × 100
```

### Detection Time Calculation
```
Detection Time = Time of Detection - Time of Threat Activity
```

## KPI Monitoring and Reporting

### Daily Monitoring
- **Detection Metrics**: Monitor detection coverage and effectiveness daily
- **Performance Metrics**: Monitor dashboard performance and query execution times
- **Alert Metrics**: Monitor alert volumes and response times

### Weekly Reporting
- **Threat Hunting Summary**: Weekly summary of hunting activities and results
- **Detection Effectiveness**: Weekly analysis of detection performance
- **Operational Metrics**: Weekly analysis of dashboard performance and usage

### Monthly Analysis
- **Trend Analysis**: Monthly analysis of KPI trends and patterns
- **Improvement Recommendations**: Monthly recommendations for KPI improvement
- **Benchmarking**: Monthly comparison against industry benchmarks

## KPI Improvement Strategies

### Detection Improvement
- **Rule Tuning**: Regular tuning of detection rules to improve accuracy
- **Threat Intelligence**: Integration of threat intelligence to enhance detection
- **Machine Learning**: Implementation of ML-based detection capabilities

### Hunting Improvement
- **Query Optimization**: Regular optimization of hunting queries
- **Technique Coverage**: Expansion of hunting coverage for additional techniques
- **Automation**: Implementation of automated hunting capabilities

### Operational Improvement
- **Performance Optimization**: Regular optimization of dashboard performance
- **User Training**: Training for analysts on effective dashboard usage
- **Process Improvement**: Continuous improvement of hunting processes

## Related Documentation

- [Dashboard Overview](dashboard_overview.md)
- [Dashboard References](references.md)
- [APT TTP Hunt Dashboard JSON](apt_ttp_hunt_dashboard.json)

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Splunk Dashboard Best Practices](https://docs.splunk.com/)
