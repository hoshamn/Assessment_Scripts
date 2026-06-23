# Deployment Guide

## Production Deployment for Microsoft Logs AI Analyzer

This guide covers deploying the analyzer in a production Microsoft environment.

## Prerequisites

### System Requirements

- **Operating System**: Windows Server 2016+ (for full functionality) or any OS for remote collection
- **Python**: 3.8 or higher
- **Memory**: Minimum 4GB RAM, recommended 8GB+
- **Disk Space**: Minimum 10GB for logs and analysis data
- **Network**: Access to monitored servers and internet for LLM APIs

### Access Requirements

- Administrator access on monitored servers (for log collection)
- Domain Admin rights (for Active Directory monitoring)
- Exchange Admin rights (for Exchange monitoring)
- API access to at least one LLM service

### Service Accounts

Create a dedicated service account with appropriate permissions:

```powershell
# Create service account
New-ADUser -Name "svc_loganalyzer" `
  -AccountPassword (Read-Host -AsSecureString "Enter Password") `
  -Enabled $true `
  -PasswordNeverExpires $true `
  -CannotChangePassword $false

# Add to required groups
Add-ADGroupMember -Identity "Event Log Readers" -Members "svc_loganalyzer"
Add-ADGroupMember -Identity "Performance Monitor Users" -Members "svc_loganalyzer"
```

## Installation Steps

### 1. Server Preparation

```powershell
# Update system
Install-WindowsUpdate -MicrosoftUpdate

# Install Python (if not already installed)
# Download from: https://www.python.org/downloads/

# Verify installation
python --version
pip --version
```

### 2. Clone and Setup

```bash
# Clone repository
git clone <repository-url>
cd Assessment_Scripts

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration

```bash
# Copy example configuration
cp config/config.example.yaml config/config.yaml

# Edit configuration
notepad config/config.yaml
```

Key configuration areas:

#### LLM Provider
```yaml
llm:
  provider: claude  # or openai, gemini
  claude:
    model: claude-3-5-sonnet-20241022
    max_tokens: 4096
```

#### Log Collection
```yaml
log_collection:
  interval_seconds: 300  # 5 minutes

  servers:
    - name: DC01
      type: domain_controller
      hostname: dc01.company.com
      enabled: true
```

#### Alert Configuration
```yaml
alerts:
  enabled: true
  email:
    enabled: true
    smtp_server: smtp.company.com
    smtp_port: 587
    to_addresses:
      - it-team@company.com
```

### 4. Credential Setup

```bash
# Run credential setup
python scripts/setup_credentials.py
```

Follow prompts to enter:
- LLM API keys
- SMTP credentials (optional)

### 5. Test Configuration

```bash
# Test configuration and connectivity
python main.py --mode test
```

Verify all checks pass:
- ✓ Config Valid
- ✓ LLM Connection
- ✓ Credential Storage
- ✓ All Collectors

### 6. Initial Run

```bash
# Run one-time analysis
python main.py --mode analyze
```

Check output in `data/reports/` directory.

## Running as a Service

### Windows Service (NSSM)

1. **Install NSSM** (Non-Sucking Service Manager):
```powershell
# Download from: https://nssm.cc/download
# Or via Chocolatey:
choco install nssm
```

2. **Create Service**:
```powershell
# Install service
nssm install MSLogAnalyzer "C:\Path\To\Python\python.exe" `
  "C:\Path\To\Assessment_Scripts\main.py --mode monitor"

# Configure service
nssm set MSLogAnalyzer AppDirectory "C:\Path\To\Assessment_Scripts"
nssm set MSLogAnalyzer DisplayName "Microsoft Logs AI Analyzer"
nssm set MSLogAnalyzer Description "AI-powered log analysis for Microsoft environment"
nssm set MSLogAnalyzer Start SERVICE_AUTO_START

# Set service account
nssm set MSLogAnalyzer ObjectName "DOMAIN\svc_loganalyzer" "password"

# Start service
nssm start MSLogAnalyzer
```

3. **Manage Service**:
```powershell
# Check status
nssm status MSLogAnalyzer

# Stop service
nssm stop MSLogAnalyzer

# Restart service
nssm restart MSLogAnalyzer

# Remove service
nssm remove MSLogAnalyzer confirm
```

### Task Scheduler (Alternative)

```powershell
# Create scheduled task
$action = New-ScheduledTaskAction `
  -Execute "python.exe" `
  -Argument "C:\Path\To\Assessment_Scripts\main.py --mode monitor" `
  -WorkingDirectory "C:\Path\To\Assessment_Scripts"

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal `
  -UserID "DOMAIN\svc_loganalyzer" `
  -LogonType ServiceAccount `
  -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -RestartCount 3 `
  -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask `
  -TaskName "MSLogAnalyzer" `
  -Action $action `
  -Trigger $trigger `
  -Principal $principal `
  -Settings $settings
```

## Security Hardening

### File Permissions

```powershell
# Restrict access to configuration and data directories
$acl = Get-Acl "C:\Path\To\Assessment_Scripts\config"
$acl.SetAccessRuleProtection($true, $false)

# Add service account
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "DOMAIN\svc_loganalyzer",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($rule)

# Add administrators
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($rule)

Set-Acl "C:\Path\To\Assessment_Scripts\config" $acl
Set-Acl "C:\Path\To\Assessment_Scripts\data" $acl
```

### Firewall Rules

```powershell
# Only if remote access is needed
New-NetFirewallRule `
  -DisplayName "MSLogAnalyzer API" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8080 `
  -Action Allow `
  -Profile Domain
```

### Encryption

Ensure TLS 1.3 for all API communications:

```yaml
# In config.yaml
security:
  network:
    use_tls: true
    verify_certificates: true
```

## Monitoring the Analyzer

### Log Monitoring

```powershell
# View application logs
Get-Content "C:\Path\To\Assessment_Scripts\data\logs\analyzer_*.log" -Tail 50 -Wait
```

### Health Checks

Create a monitoring script:

```powershell
# health_check.ps1
$service = Get-Service -Name "MSLogAnalyzer" -ErrorAction SilentlyContinue

if ($service.Status -ne "Running") {
    Send-MailMessage `
        -To "admin@company.com" `
        -From "monitoring@company.com" `
        -Subject "MSLogAnalyzer Service Down" `
        -Body "The MSLogAnalyzer service is not running" `
        -SmtpServer "smtp.company.com"
}

# Check last analysis time
$lastReport = Get-ChildItem "C:\Path\To\Assessment_Scripts\data\reports\summary_*.json" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$age = (Get-Date) - $lastReport.LastWriteTime

if ($age.TotalMinutes -gt 30) {
    Send-MailMessage `
        -To "admin@company.com" `
        -From "monitoring@company.com" `
        -Subject "MSLogAnalyzer Not Producing Reports" `
        -Body "Last report is $($age.TotalMinutes) minutes old" `
        -SmtpServer "smtp.company.com"
}
```

### Performance Monitoring

```powershell
# Monitor resource usage
Get-Process python | Select-Object `
    ProcessName,
    @{Name="CPU(%)";Expression={$_.CPU}},
    @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet/1MB,2)}}
```

## Backup and Recovery

### Backup Script

```powershell
# backup.ps1
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = "C:\Backups\MSLogAnalyzer\$timestamp"

New-Item -ItemType Directory -Path $backupDir -Force

# Backup configuration
Copy-Item "C:\Path\To\Assessment_Scripts\config\*.yaml" "$backupDir\config\" -Recurse

# Backup credentials (encrypted)
Copy-Item "C:\Path\To\Assessment_Scripts\config\.cred*" "$backupDir\config\" -Recurse
Copy-Item "C:\Path\To\Assessment_Scripts\config\.key" "$backupDir\config\" -Recurse

# Backup patterns
Copy-Item "C:\Path\To\Assessment_Scripts\data\patterns\*" "$backupDir\patterns\" -Recurse

# Backup recent reports (last 30 days)
Get-ChildItem "C:\Path\To\Assessment_Scripts\data\reports\" -Recurse |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
    Copy-Item -Destination "$backupDir\reports\" -Force

# Compress
Compress-Archive -Path $backupDir -DestinationPath "$backupDir.zip"
Remove-Item $backupDir -Recurse -Force

# Cleanup old backups (keep 30 days)
Get-ChildItem "C:\Backups\MSLogAnalyzer\*.zip" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Force
```

### Recovery

```powershell
# Extract backup
Expand-Archive -Path "C:\Backups\MSLogAnalyzer\20240101_120000.zip" `
  -DestinationPath "C:\Recovery\MSLogAnalyzer"

# Restore configuration
Copy-Item "C:\Recovery\MSLogAnalyzer\config\*" `
  "C:\Path\To\Assessment_Scripts\config\" -Force

# Restore patterns
Copy-Item "C:\Recovery\MSLogAnalyzer\patterns\*" `
  "C:\Path\To\Assessment_Scripts\data\patterns\" -Force
```

## Scaling Considerations

### Distributed Collection

For large environments, deploy multiple collectors:

1. **Central Analyzer**: Runs main analysis and LLM integration
2. **Regional Collectors**: Collect logs from local servers

### Load Balancing

For high-volume environments:

```yaml
# In config.yaml
performance:
  worker_threads: 8  # Increase based on CPU cores

  batching:
    enabled: true
    max_batch_size: 200
    batch_interval_seconds: 120
```

### Database Considerations

For long-term storage, consider integrating with:
- SQL Server
- Elasticsearch
- Azure Log Analytics

## Troubleshooting

### Common Issues

**Issue**: Service won't start
```powershell
# Check event log
Get-EventLog -LogName Application -Source "MSLogAnalyzer" -Newest 20
```

**Issue**: No logs collected
```powershell
# Verify service account permissions
Test-Path "C:\Windows\System32\winevt\Logs\System.evtx" -ErrorAction Stop

# Test WMI access
Get-WmiObject -Class Win32_NTLogEvent -ComputerName localhost
```

**Issue**: LLM API errors
- Check API key validity
- Verify network connectivity to API endpoints
- Review rate limiting configuration

## Support

For issues and support:
- Review application logs in `data/logs/`
- Check configuration in `config/config.yaml`
- Consult documentation in `docs/`

## Maintenance

### Regular Tasks

**Daily**:
- Monitor service status
- Review critical alerts

**Weekly**:
- Review analysis reports
- Check disk space usage
- Verify backup completion

**Monthly**:
- Review and update patterns
- Update Python dependencies: `pip install -r requirements.txt --upgrade`
- Review API usage and costs
- Security updates

### Updates

```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Restart service
nssm restart MSLogAnalyzer
```
