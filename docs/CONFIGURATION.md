# Configuration Guide

Complete guide to configuring the Microsoft Logs AI Analyzer.

## Configuration File

The main configuration file is `config/config.yaml`. Copy from `config/config.example.yaml` to get started.

## Configuration Sections

### 1. General Settings

```yaml
general:
  environment: production  # production, staging, development
  log_level: INFO         # DEBUG, INFO, WARNING, ERROR, CRITICAL
  data_directory: ./data  # Where to store logs and analysis data
  timezone: UTC           # Timezone for timestamps
```

**Options**:
- `environment`: Sets the operational environment
- `log_level`: Controls verbosity of application logging
- `data_directory`: Base directory for all data storage
- `timezone`: Timezone for log timestamps

### 2. LLM Provider Configuration

```yaml
llm:
  provider: claude  # claude, openai, gemini

  # Claude (Anthropic) settings
  claude:
    model: claude-3-5-sonnet-20241022
    max_tokens: 4096
    temperature: 0.3
    api_endpoint: https://api.anthropic.com/v1/messages

  # OpenAI settings
  openai:
    model: gpt-4-turbo-preview
    max_tokens: 4096
    temperature: 0.3
    api_endpoint: https://api.openai.com/v1/chat/completions

  # Google Gemini settings
  gemini:
    model: gemini-pro
    max_tokens: 4096
    temperature: 0.3
```

**Model Selection**:

**Claude (Recommended for production)**:
- `claude-3-5-sonnet-20241022`: Best balance of cost and performance
- `claude-3-opus-20240229`: Highest accuracy, higher cost
- `claude-3-haiku-20240307`: Fastest, lowest cost

**OpenAI**:
- `gpt-4-turbo-preview`: Latest GPT-4, best quality
- `gpt-4`: Stable GPT-4
- `gpt-3.5-turbo`: Lower cost, good performance

**Gemini**:
- `gemini-pro`: Standard model
- `gemini-ultra`: Most capable (when available)

**Temperature**: Controls randomness (0.0 = deterministic, 1.0 = creative)
- Use 0.1-0.3 for log analysis (more factual)
- Use 0.5-0.7 for recommendations (more creative)

**Rate Limiting**:

```yaml
llm:
  rate_limit:
    requests_per_minute: 50
    requests_per_day: 5000
```

Adjust based on your API plan limits.

**Batching** (Cost Optimization):

```yaml
llm:
  batching:
    enabled: true
    max_batch_size: 100      # Logs per batch
    batch_interval_seconds: 60  # Wait time before processing batch
```

### 3. Log Collection Settings

```yaml
log_collection:
  interval_seconds: 300  # Collection interval (5 minutes)
  max_logs_per_collection: 1000
  retention_days: 30

  servers:
    - name: DC01
      type: domain_controller
      hostname: dc01.contoso.com
      enabled: true

    - name: EXCH01
      type: exchange
      hostname: exch01.contoso.com
      enabled: true
```

**Server Types**:
- `domain_controller`: Active Directory Domain Controller
- `exchange`: Microsoft Exchange Server
- `iis`: IIS Web Server
- `sql_server`: SQL Server
- `file_server`: File Server
- `generic`: Generic Windows Server

**Log Sources**:

#### Windows Event Logs

```yaml
log_collection:
  sources:
    windows_event_logs:
      enabled: true
      logs:
        - System
        - Application
        - Security
      event_levels:
        - Error
        - Warning
        - Critical
      event_ids: []  # Empty = all events, or specify: [1000, 1001, 1002]
```

#### Active Directory

```yaml
log_collection:
  sources:
    active_directory:
      enabled: true
      logs:
        - Directory Service
        - DFS Replication
        - DNS Server
      critical_events:
        - 1644  # AD database corruption
        - 2042  # Replication failure
        - 4740  # Account lockout
```

#### Exchange

```yaml
log_collection:
  sources:
    exchange:
      enabled: true
      logs:
        - MSExchange Management
        - MSExchange ADAccess
        - MSExchangeTransport
      monitor_mailflow: true
      monitor_database: true
```

#### IIS

```yaml
log_collection:
  sources:
    iis:
      enabled: true
      log_path: C:\inetpub\logs\LogFiles
      monitor_errors: true
      monitor_performance: true
```

#### Azure Data Factory

```yaml
log_collection:
  sources:
    azure_data_factory:
      enabled: false
      subscription_id: your-subscription-id
      resource_group: your-resource-group
      factory_name: your-adf-name
```

#### Custom Logs

```yaml
log_collection:
  sources:
    custom_logs:
      enabled: true
      paths:
        - path: C:\CustomLogs\*.log
          format: text
        - path: C:\Apps\*.json
          format: json
```

### 4. Analysis Settings

```yaml
analysis:
  # Real-time analysis for critical events
  realtime:
    enabled: true
    critical_threshold: 1  # Number of critical events to trigger

  # Batch analysis
  batch:
    enabled: true
    interval_minutes: 15

  # Pattern learning
  pattern_learning:
    enabled: true
    min_occurrences: 3           # Minimum occurrences to establish pattern
    learning_window_days: 7      # Historical data window
    auto_update: true            # Auto-update pattern database

  # Anomaly detection
  anomaly_detection:
    enabled: true
    sensitivity: medium  # low, medium, high
    baseline_days: 14

  # Issue classification
  severity_levels:
    critical:
      keywords:
        - "database corruption"
        - "service crashed"
        - "domain controller"
      auto_alert: true

    high:
      keywords:
        - "high CPU"
        - "memory exhausted"
      auto_alert: true

    medium:
      keywords:
        - "warning"
        - "timeout"
      auto_alert: false

    low:
      keywords:
        - "information"
      auto_alert: false
```

**Sensitivity Levels**:
- `low`: Only flag severe anomalies (fewer false positives)
- `medium`: Balanced approach (recommended)
- `high`: Flag minor anomalies (more false positives, better early detection)

### 5. Alert Configuration

```yaml
alerts:
  enabled: true

  # Email notifications
  email:
    enabled: true
    smtp_server: smtp.company.com
    smtp_port: 587
    use_tls: true
    from_address: msloganalyzer@company.com
    to_addresses:
      - it-team@company.com
      - oncall@company.com
    daily_summary: true
    summary_time: "08:00"

  # Webhook notifications
  webhook:
    enabled: false
    url: https://your-webhook-url.com/alerts
    method: POST
    headers:
      Content-Type: application/json

  # Microsoft Teams
  teams:
    enabled: false
    webhook_url: https://outlook.office.com/webhook/...

  # Slack
  slack:
    enabled: false
    webhook_url: https://hooks.slack.com/services/...

  # Alert rules
  rules:
    suppress_during_maintenance: true
    deduplication_window_minutes: 30
    escalation:
      enabled: true
      threshold: 3
      window_minutes: 60
```

**Alert Channels**:

1. **Email**: Traditional email alerts
2. **Webhook**: Custom webhook for integration
3. **Teams**: Microsoft Teams channel notifications
4. **Slack**: Slack channel notifications

**Alert Rules**:
- `suppress_during_maintenance`: Don't alert during maintenance windows
- `deduplication_window_minutes`: Don't send duplicate alerts within window
- `escalation`: Escalate after threshold breached

### 6. Security Settings

```yaml
security:
  # Credential storage
  credential_storage: dpapi  # dpapi (Windows), encrypted_file, environment

  # Encryption
  encryption:
    enabled: true
    algorithm: AES-256-GCM

  # Data masking
  data_masking:
    enabled: true
    mask_patterns:
      - pattern: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        type: email
      - pattern: '\b\d{3}-\d{2}-\d{4}\b'
        type: ssn

  # Access control
  access_control:
    enabled: true
    require_authentication: true

  # Audit logging
  audit_log:
    enabled: true
    log_all_access: true
    retention_days: 90
```

**Credential Storage Options**:
- `dpapi`: Windows Data Protection API (Windows only, most secure)
- `encrypted_file`: Encrypted file storage (cross-platform)
- `environment`: Environment variables (least secure, for development only)

**Data Masking**:
Add custom patterns to mask sensitive data:

```yaml
security:
  data_masking:
    mask_patterns:
      - pattern: 'custom_pattern_regex'
        type: custom_type
```

### 7. Performance Settings

```yaml
performance:
  worker_threads: 4  # Parallel processing threads

  cache:
    enabled: true
    max_size_mb: 500
    ttl_minutes: 60

  db_pool:
    min_connections: 2
    max_connections: 10
```

**Worker Threads**: Set based on CPU cores
- Small environment: 2-4
- Medium environment: 4-8
- Large environment: 8-16

### 8. Dashboard Settings

```yaml
dashboard:
  enabled: true
  host: 0.0.0.0  # Listen on all interfaces
  port: 8080

  authentication:
    enabled: true
    username: admin
    # Password stored in credential manager

  refresh_interval: 30  # seconds
```

## Environment-Specific Configurations

### Development

```yaml
general:
  environment: development
  log_level: DEBUG

llm:
  claude:
    model: claude-3-haiku-20240307  # Cheaper for testing
    max_tokens: 2048

log_collection:
  interval_seconds: 600  # Less frequent

alerts:
  enabled: false  # Don't send alerts in dev
```

### Production

```yaml
general:
  environment: production
  log_level: INFO

llm:
  claude:
    model: claude-3-5-sonnet-20241022

log_collection:
  interval_seconds: 300

alerts:
  enabled: true
  email:
    enabled: true
```

## Validation

Test your configuration:

```bash
python main.py --mode test
```

This will validate:
- Configuration syntax
- Credential availability
- Collector connectivity
- LLM API access

## Best Practices

1. **Start Simple**: Enable one collector at a time
2. **Monitor Costs**: Watch LLM API usage
3. **Adjust Sensitivity**: Tune based on your environment
4. **Review Patterns**: Regularly review learned patterns
5. **Secure Credentials**: Use DPAPI on Windows
6. **Test Alerts**: Send test alerts before production
7. **Backup Config**: Keep configuration backups
8. **Document Changes**: Comment configuration changes

## Troubleshooting

**Issue**: Too many false positives
```yaml
analysis:
  anomaly_detection:
    sensitivity: low  # Reduce sensitivity
```

**Issue**: Missing critical issues
```yaml
analysis:
  anomaly_detection:
    sensitivity: high  # Increase sensitivity

  realtime:
    enabled: true
    critical_threshold: 1
```

**Issue**: High API costs
```yaml
llm:
  batching:
    enabled: true
    batch_interval_seconds: 300  # Longer batching

  claude:
    model: claude-3-haiku-20240307  # Cheaper model
```

**Issue**: Performance problems
```yaml
performance:
  worker_threads: 8  # Increase threads
  cache:
    enabled: true
    max_size_mb: 1000  # Larger cache
```
