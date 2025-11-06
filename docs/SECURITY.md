# Security Guide

## Security Best Practices for Microsoft Logs AI Analyzer

This guide covers security considerations for deploying the analyzer in production environments.

## Overview

The analyzer handles sensitive log data and uses cloud APIs, requiring multiple layers of security:

1. **Credential Security**: Protecting API keys and passwords
2. **Data Protection**: Securing log data and analysis results
3. **Network Security**: Securing communications
4. **Access Control**: Limiting who can access the system
5. **Audit & Compliance**: Tracking and logging access

## Credential Management

### Storage Methods

**Windows DPAPI (Recommended for Windows)**:
- Uses Windows Data Protection API
- Credentials encrypted with machine key
- Automatically selected on Windows systems
- Most secure option for Windows

**Encrypted File Storage**:
- Cross-platform alternative
- Uses AES-256-GCM encryption
- Machine-specific key derivation
- Good for non-Windows systems

**Environment Variables** (Development Only):
- NOT for production use
- Credentials in plain text
- Only for testing

### Configuration

```yaml
security:
  credential_storage: dpapi  # or encrypted_file
```

### Setup

```bash
python scripts/setup_credentials.py
```

### Best Practices

1. **Use Service Accounts**: Create dedicated service accounts
2. **Rotate Keys**: Regularly rotate API keys and passwords
3. **Limit Access**: Restrict file system permissions
4. **No Hard-coding**: Never hard-code credentials
5. **Audit**: Log all credential access

## Data Protection

### Data Masking

Automatically redacts sensitive information before AI analysis:

```yaml
security:
  data_masking:
    enabled: true
    mask_patterns:
      - pattern: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        type: email
      - pattern: 'password["\s:=]+[^\s"]*'
        type: password
```

**Default Masking**:
- Email addresses
- IP addresses
- Credit card numbers
- SSN
- Passwords
- API keys
- Windows SIDs
- GUIDs

### Custom Patterns

Add organization-specific patterns:

```yaml
security:
  data_masking:
    mask_patterns:
      - pattern: 'COMPANY-\d{6}'
        type: employee_id
      - pattern: 'PROJECT-[A-Z]{3}-\d{4}'
        type: project_code
```

### Encryption

#### In Transit

```yaml
security:
  network:
    use_tls: true
    verify_certificates: true
```

- All API communications use TLS 1.3
- Certificate validation enabled
- No self-signed certificates in production

#### At Rest

```yaml
security:
  encryption:
    enabled: true
    algorithm: AES-256-GCM
```

- Configuration files encrypted
- Credential storage encrypted
- Optional: Encrypt logs on disk

### Data Retention

```yaml
log_collection:
  retention_days: 30

security:
  audit_log:
    retention_days: 90
```

**Best Practices**:
- Comply with regulatory requirements (GDPR, HIPAA, etc.)
- Regularly purge old data
- Document retention policies

## Network Security

### Firewall Configuration

```powershell
# Outbound to LLM APIs (required)
New-NetFirewallRule -DisplayName "MSLogAnalyzer-LLM-Out" `
  -Direction Outbound `
  -Protocol TCP `
  -RemoteAddress * `
  -RemotePort 443 `
  -Action Allow

# Inbound dashboard (optional, if using web interface)
New-NetFirewallRule -DisplayName "MSLogAnalyzer-Dashboard" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8080 `
  -Action Allow `
  -Profile Domain
```

### API Endpoints

Whitelist these endpoints:

**Claude (Anthropic)**:
- `api.anthropic.com` (443)

**OpenAI**:
- `api.openai.com` (443)

**Google Gemini**:
- `generativelanguage.googleapis.com` (443)

### Network Isolation

For highly sensitive environments:

1. Deploy in isolated network segment
2. Use proxy for API access
3. Enable network monitoring
4. Implement data loss prevention (DLP)

## Access Control

### File System Permissions

```powershell
# Windows - Restrict to service account and admins only
$path = "C:\Path\To\Assessment_Scripts"
$acl = Get-Acl $path
$acl.SetAccessRuleProtection($true, $false)

# Service account
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "DOMAIN\svc_loganalyzer", "FullControl",
    "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)

# Administrators
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "FullControl",
    "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)

Set-Acl $path $acl
```

### Service Account

Create dedicated service account with minimal permissions:

```powershell
# Required permissions:
# - Event Log Readers
# - Performance Monitor Users
# - Network access for API calls
# - Read/Write to application directory

New-ADUser -Name "svc_loganalyzer" `
  -AccountPassword (Read-Host -AsSecureString) `
  -PasswordNeverExpires $true `
  -Enabled $true

Add-ADGroupMember -Identity "Event Log Readers" -Members "svc_loganalyzer"
Add-ADGroupMember -Identity "Performance Monitor Users" -Members "svc_loganalyzer"
```

### Dashboard Authentication

```yaml
dashboard:
  authentication:
    enabled: true
    username: admin
    # Password in credential manager
```

Enable authentication for web dashboard.

## Audit & Compliance

### Audit Logging

```yaml
security:
  audit_log:
    enabled: true
    log_all_access: true
    retention_days: 90
```

**Logged Events**:
- Application starts/stops
- Configuration changes
- Credential access
- Analysis runs
- Alert sends
- Errors and exceptions

### Compliance Considerations

#### GDPR (EU)

- Enable data masking
- Set appropriate retention periods
- Document data processing
- Implement right to erasure

#### HIPAA (Healthcare)

- Enable encryption at rest
- Enable audit logging
- Use role-based access control
- Regular security assessments

#### SOC 2

- Enable comprehensive logging
- Implement change control
- Regular backups
- Incident response procedures

## Incident Response

### Security Incident Checklist

1. **Detect**: Monitor logs for suspicious activity
2. **Contain**: Stop service if compromised
3. **Investigate**: Review audit logs
4. **Remediate**: Rotate credentials, patch vulnerabilities
5. **Document**: Record incident and response
6. **Review**: Post-incident analysis

### Compromise Response

If credentials are compromised:

```bash
# 1. Stop service immediately
nssm stop MSLogAnalyzer

# 2. Rotate all API keys
# - Revoke old keys at provider
# - Generate new keys
# - Update with setup script
python scripts/setup_credentials.py

# 3. Review audit logs
Get-Content data/logs/audit_*.log | Select-String "credential"

# 4. Restart service
nssm start MSLogAnalyzer
```

## Security Monitoring

### Monitor for:

1. **Failed Authentication Attempts**
```powershell
Get-Content data/logs/analyzer_*.log | Select-String "authentication failed"
```

2. **Unusual API Activity**
```powershell
Get-Content data/logs/analyzer_*.log | Select-String "rate limit"
```

3. **Configuration Changes**
```powershell
Get-FileHash config/config.yaml
# Compare with known good hash
```

4. **Unauthorized Access**
```powershell
# Windows Security Event Log
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4663
    Path='*Assessment_Scripts*'
}
```

## Hardening Checklist

- [ ] Use dedicated service account
- [ ] Enable data masking
- [ ] Use DPAPI for credentials (Windows)
- [ ] Enable TLS 1.3 for all communications
- [ ] Restrict file system permissions
- [ ] Enable audit logging
- [ ] Configure firewall rules
- [ ] Set appropriate data retention
- [ ] Enable dashboard authentication
- [ ] Regular credential rotation
- [ ] Monitor security logs
- [ ] Keep Python and dependencies updated
- [ ] Backup configuration securely
- [ ] Document security procedures
- [ ] Regular security assessments

## Vulnerability Management

### Keep Updated

```bash
# Update Python packages
pip install -r requirements.txt --upgrade

# Check for vulnerabilities
pip install safety
safety check

# Update application
git pull origin main
```

### Security Updates

Subscribe to security advisories:
- Anthropic security bulletins
- OpenAI security updates
- Microsoft Security Response Center
- Python security advisories

## Contact

For security concerns or to report vulnerabilities:
- Review audit logs
- Contact security team
- Follow incident response procedures

## Additional Resources

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Microsoft Security Best Practices](https://docs.microsoft.com/en-us/security/)
