# Investigation Procedure and Findings

**Document Type:** Analysis

**Case ID:** 008-ssh-bruteforce-auth-abuse-post-exploitation  
**Time Standard:** UTC  

## Investigation Workflow

### Step 1 – Identify Initial Indicators

- Reviewed Elastic SIEM dashboards for SSH authentication activity  
- Identified high volume of failed authentication attempts  
- Noted repeated targeting of common administrative accounts  

Initial observation:
- Username `admin` had the highest number of failed login attempts (76)

## Step 2 – Analyze Failed Authentication Patterns

- Queried `system.auth` dataset for failed authentication events  
- Performed frequency analysis on usernames  

Findings:
- Brute-force behavior targeting administrative accounts  
- Multiple usernames targeted including:
  - `admin`
  - `student`
  - `ansible`

## Step 3 – Perform Geographic Analysis

- Used GeoIP fields (`source.geo.*`) to group failed login attempts by country  
- Aggregated results using KQL queries  

Findings:
- Highest volume of failed authentication attempts from:
  - United States (193 events)  
- Total failed attempts analyzed:
  - 523 events across 14 countries  

Interpretation:
- Attack traffic is distributed, likely leveraging compromised or proxy-based infrastructure  

## Step 4 – Identify Successful Authentication Events

- Filtered for SSH authentication events using public key method  
- Queried:
  - `system.auth.ssh.method: publickey`  

Findings:
- Successful SSH authentication events observed  
- Primary source IP:
  - `91[.]75[.]13[.]46` (7 events)  

Interpretation:
- Indicates compromise or unauthorized use of SSH keys  

## Step 5 – Investigate Targeted Authentication Attempts

### Russian Activity

- Filtered logs for:
  - `source.geo.country_iso_code: "RU"`
  - `user.name: "student"`  

Findings:
- Source IP:
  - `185[.]51[.]61[.]82`  

### China-Based Activity

- Filtered logs for:
  - `user.name: "ansible"`
  - Location: Xiamen, China  

Findings:
- Source IP:
  - `120[.]41[.]81[.]81`  

Interpretation:
- Attackers targeted both administrative and service-related accounts  
- Indicates credential discovery and expansion attempts  

## Step 6 – Analyze Windows Authentication Logs

- Investigated endpoint:
  - `EC2AMAZ-PARMDQI`  

- Queried Windows Security logs:
  - Event Code: 4625 (failed logon)  

Findings:
- Total failed login attempts:
  - 22,267  

Interpretation:
- Indicates large-scale brute-force attack targeting Windows authentication  

## Step 7 – Identify Attacker Host Attribution

- Reviewed `source.domain` field in authentication logs  

Findings:
- Hostname:
  - `WIN-98F3GJOHHDS`  

Interpretation:
- Suggests attacker utilized a Windows-based system for launching attacks  

## Step 8 – Analyze SIEM Detection Alerts

- Reviewed alerts in Elastic Security → Alerts  
- Filtered by IP:
  - `20[.]115[.]105[.]92`  

Findings:
- Most frequent alert:
  - Privileged Account Brute Force (~248 occurrences)  

Other alerts:
- Multiple Logon Failure from Same Source Address  
- Interactive Terminal Spawned via Python  
- PowerShell Suspicious Payload Encoded and Compressed  
- Unusual Persistence via Services Registry  
- Potential Process Injection via PowerShell  

Interpretation:
- Confirms transition from brute-force phase to post-exploitation activity  

## Step 9 – Investigate Process Execution Indicators

- Filtered alerts for:
  - `Interactive Terminal Spawned via Python`  

Findings:
- Process identified:
  - `python3`  

Interpretation:
- Indicates attacker achieved command execution capability and established interactive shell access  

## Summary of Procedure

The investigation followed a structured workflow:

1. Identification of abnormal authentication activity  
2. Analysis of brute-force patterns  
3. Geographic attribution of attack sources  
4. Detection of successful authentication events  
5. Investigation of targeted account activity  
6. Analysis of Windows authentication logs  
7. Attribution of attacker infrastructure  
8. Review of SIEM detection alerts  
9. Confirmation of post-exploitation behavior  

This methodology enabled reconstruction of the attack lifecycle from initial access attempts through post-exploitation activity.
