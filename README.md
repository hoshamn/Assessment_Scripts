# Microsoft Logs AI Analyzer

A production-ready, secure system for collecting and analyzing Microsoft environment logs using AI/LLM services (Claude, ChatGPT, Google Gemini) to proactively detect issues and provide actionable recommendations.

## Overview

This system is designed for critical production environments managing Microsoft services including:
- Windows Servers
- Active Directory
- Microsoft Exchange
- Azure Data Factory (ADF)
- IIS
- SQL Server
- And other Microsoft services

## Key Features

- **Multi-LLM Support**: Works with Claude (Anthropic), ChatGPT (OpenAI), and Google Gemini
- **Proactive Analysis**: Detects issues before they impact production
- **Pattern Learning**: Learns from historical logs to improve detection
- **Secure by Default**: Enterprise-grade security for sensitive log data
- **Minimal Requirements**: Simple deployment with minimal dependencies
- **Production Ready**: Comprehensive error handling, logging, and monitoring

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Microsoft Environment                     │
│  (Windows Servers, AD, Exchange, ADF, IIS, SQL, etc.)      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  Log Collection Layer                        │
│  (Event Logs, Application Logs, Security Logs, Custom)     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                 Log Processing & Storage                     │
│         (Filtering, Normalization, Deduplication)           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   AI Analysis Engine                         │
│     (LLM Integration, Pattern Recognition, Learning)        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Alert & Reporting System                        │
│    (Dashboard, Email Alerts, Action Recommendations)        │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Windows Server with PowerShell 5.1+
- API access to at least one LLM service (Claude/ChatGPT/Gemini)
- Network access to monitored servers

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Assessment_Scripts
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure the system:
```bash
# Copy example configuration
cp config/config.example.yaml config/config.yaml

# Edit configuration with your settings
notepad config/config.yaml
```

4. Set up secure credentials:
```bash
python scripts/setup_credentials.py
```

5. Run initial setup:
```bash
python scripts/setup.py
```

### Running the Analyzer

**Continuous Monitoring Mode:**
```bash
python main.py --mode monitor
```

**One-time Analysis:**
```bash
python main.py --mode analyze
```

**Test Configuration:**
```bash
python main.py --mode test
```

## Configuration

Edit `config/config.yaml` to customize:

- **Log Sources**: Servers and services to monitor
- **LLM Provider**: Choose between Claude, ChatGPT, or Gemini
- **Analysis Settings**: Thresholds, patterns, and learning parameters
- **Alert Settings**: Email, webhooks, and notification preferences
- **Security Settings**: Encryption, access control, and data retention

See [Configuration Guide](docs/CONFIGURATION.md) for detailed options.

## Security Features

- **Encrypted Credentials**: API keys stored using Windows DPAPI or AES-256
- **Secure Transmission**: TLS 1.3 for all communications
- **Access Control**: Role-based access for different log types
- **Data Masking**: PII and sensitive data automatically redacted
- **Audit Trail**: Complete logging of all analysis activities
- **Compliance Ready**: Supports GDPR, HIPAA, SOC2 requirements

## Project Structure

```
Assessment_Scripts/
├── main.py                          # Main application entry point
├── requirements.txt                 # Python dependencies
├── config/
│   ├── config.yaml                  # Main configuration
│   ├── config.example.yaml          # Example configuration
│   └── log_patterns.yaml            # Known log patterns
├── src/
│   ├── collectors/                  # Log collection modules
│   │   ├── windows_event_collector.py
│   │   ├── ad_collector.py
│   │   ├── exchange_collector.py
│   │   ├── adf_collector.py
│   │   └── iis_collector.py
│   ├── analyzers/                   # AI analysis modules
│   │   ├── llm_client.py            # LLM integration
│   │   ├── pattern_analyzer.py      # Pattern recognition
│   │   └── anomaly_detector.py      # Anomaly detection
│   ├── storage/                     # Data storage
│   │   ├── log_storage.py
│   │   └── pattern_storage.py
│   ├── alerts/                      # Alert system
│   │   ├── alert_manager.py
│   │   └── notification_sender.py
│   ├── security/                    # Security utilities
│   │   ├── credential_manager.py
│   │   └── data_masking.py
│   └── utils/                       # Utility functions
│       ├── logger.py
│       └── helpers.py
├── scripts/                         # Setup and utility scripts
│   ├── setup.py
│   └── setup_credentials.py
├── data/                            # Data directory (git-ignored)
│   ├── logs/
│   ├── patterns/
│   └── reports/
├── docs/                            # Documentation
│   ├── CONFIGURATION.md
│   ├── DEPLOYMENT.md
│   ├── SECURITY.md
│   └── API.md
└── tests/                           # Unit tests
    └── ...
```

## Documentation

- [Configuration Guide](docs/CONFIGURATION.md) - Detailed configuration options
- [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment steps
- [Security Guide](docs/SECURITY.md) - Security best practices
- [API Documentation](docs/API.md) - API reference and examples

## Monitoring Dashboard

Access the web dashboard at `http://localhost:8080` (default) to:
- View real-time analysis results
- Browse historical patterns
- Configure alert rules
- Review recommended actions
- Monitor system health

## Support

For issues, questions, or contributions, please refer to the project repository.

## License

[Specify your license here]

## Disclaimer

This tool is designed for authorized use in your own Microsoft environment. Ensure you have proper permissions and comply with your organization's security policies.
