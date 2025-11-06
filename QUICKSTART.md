# Quick Start Guide

Get started with Microsoft Logs AI Analyzer in 5 minutes.

## Prerequisites

- Python 3.8+
- Windows Server (or remote access to Windows servers)
- API key for Claude, ChatGPT, or Gemini

## Installation

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure

```bash
# Copy example configuration
cp config/config.example.yaml config/config.yaml

# Edit with your settings
notepad config/config.yaml  # Windows
nano config/config.yaml     # Linux
```

**Minimum Required Changes**:

```yaml
llm:
  provider: claude  # or openai, gemini

log_collection:
  servers:
    - name: YourServer
      hostname: server.company.com
      enabled: true

alerts:
  email:
    smtp_server: your-smtp-server.com
    to_addresses:
      - your-email@company.com
```

### 3. Setup Credentials

```bash
python scripts/setup_credentials.py
```

Enter your LLM API key when prompted.

### 4. Test Configuration

```bash
python main.py --mode test
```

Verify all checks pass.

### 5. Run Analysis

```bash
# One-time analysis
python main.py --mode analyze

# Continuous monitoring
python main.py --mode monitor
```

## What It Does

1. **Collects** logs from your Microsoft environment
2. **Masks** sensitive data automatically
3. **Analyzes** logs using AI to detect issues
4. **Learns** patterns from historical data
5. **Alerts** you about critical issues
6. **Recommends** actions to resolve problems

## View Results

Results are saved in `data/reports/`:

```bash
# View latest analysis
cat data/reports/analysis_*.json | tail -n 1

# View summary
cat data/reports/summary_*.json | tail -n 1
```

## Run as Service

### Windows

```powershell
# Install NSSM
choco install nssm

# Create service
nssm install MSLogAnalyzer "C:\Python\python.exe" "C:\Path\To\main.py --mode monitor"

# Start service
nssm start MSLogAnalyzer
```

## Get Help

- Full documentation: `docs/`
- Configuration help: `docs/CONFIGURATION.md`
- Deployment guide: `docs/DEPLOYMENT.md`
- Security guide: `docs/SECURITY.md`

## Common Issues

**"No API key found"**:
```bash
python scripts/setup_credentials.py
```

**"Cannot collect logs"**:
- Verify service account permissions
- Check server connectivity

**"Too many API requests"**:
- Adjust rate limiting in config.yaml
- Enable batching

## Next Steps

1. Review initial analysis results
2. Adjust alert thresholds
3. Add more servers
4. Schedule regular backups
5. Monitor API usage and costs

## Support

- Check application logs: `data/logs/`
- Review configuration: `config/config.yaml`
- Read documentation: `docs/`
