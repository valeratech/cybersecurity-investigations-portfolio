# Analysis Tools and Methods

**Document Type:** Reference

**Case ID:** 008-ssh-bruteforce-auth-abuse-post-exploitation  
**Time Standard:** UTC  

## Purpose

This document enumerates all tools, queries, methods, and analytical techniques used during the investigation. This file does not contain findings or conclusions.

## Platforms and Tools

### Elastic SIEM (Elastic Stack)
- Discover (log exploration and querying)
- Dashboards (visualization of authentication activity)
- Security → Alerts (detection rule analysis)
- Field statistics and aggregation

### Data Sources
- `system.auth` dataset (SSH authentication logs)
- Windows Security Event Logs (Event ID 4624, 4625)
- GeoIP enrichment fields (`source.geo.*`)
- SIEM alert metadata (`kibana.alert.*`)

## Query Language

### Kibana Query Language (KQL)

Used for filtering, aggregation, and correlation of authentication events.

## Key Queries Used

### Failed SSH Authentication Attempts

`event.dataset : "system.auth" AND event.outcome : "failure"`

### Failed Authentication by Geo Location

`event.dataset : "system.auth" AND event.outcome : "failure" AND source.geo.city_name: *`

### Successful SSH Key-Based Authentication

`data_stream.dataset:system.auth AND system.auth.ssh.method: publickey`

### Russian Authentication Attempts Targeting 'student'

`source.geo.country_iso_code: "RU" AND user.name: "student"`

### Xiamen, China Failed Authentication ('ansible')

`user.name:"ansible" AND event.category:"authentication" AND event.outcome:"failure" AND source.geo.city_name:"Xiamen"`

### Windows Failed Logon Events (Endpoint)

`host.name:"EC2AMAZ-PARMDQI" AND winlog.channel:"Security" AND event.code:"4625"`

### Brute-Force Activity from Russia (Windows Logs)

`host.name:"EC2AMAZ-PARMDQI" AND event.category:"authentication" AND event.outcome:"failure" AND source.geo.country_name:"Russia"`

### Detection Rule Analysis (Interactive Terminal via Python)

`kibana.alert.rule.name:"Interactive Terminal Spawned via Python"`

## Analytical Methods

### Frequency Analysis
- Identified most targeted usernames
- Determined top source IPs and countries
- Measured authentication attempt volumes

### GeoIP Analysis
- Mapped authentication attempts to geographic regions
- Identified distributed attack sources

### Authentication Method Analysis
- Differentiated between password-based and key-based SSH authentication
- Identified successful authentication patterns

### Event Correlation
- Correlated Linux SSH logs with Windows authentication logs
- Linked authentication activity to SIEM alerts

### Alert Analysis
- Reviewed triggered detection rules
- Identified post-exploitation behaviors
- Mapped alerts to attacker activity phases

## Notes

- All timestamps were treated as UTC.
- All indicators were normalized and defanged prior to documentation.
- Queries were executed within Elastic SIEM using KQL.


