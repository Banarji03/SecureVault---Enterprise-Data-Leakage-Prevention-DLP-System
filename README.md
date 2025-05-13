# SecureVault DLP System

SecureVault is a comprehensive Data Loss Prevention (DLP) system designed to protect sensitive information across multiple channels.

## Features

- **File Monitoring**: Real-time monitoring of file system activities to detect potential data leaks
  - Tracks file creation, modification, and deletion events
  - Analyzes file content for sensitive information
  - Supports automatic encryption of sensitive files
  - Configurable monitoring paths and file extensions

- **Clipboard Protection**: Monitors and controls clipboard operations containing sensitive data
  - Real-time clipboard content analysis
  - Automatic encryption of sensitive clipboard data
  - Configurable blocking of sensitive content
  - Detailed logging of clipboard violations

- **Email Scanning**: Analyzes outgoing emails for sensitive content
  - Monitors email attachments and content
  - Prevents unauthorized data transmission
  - Integration with email clients

- **External Drive Detection**: Monitors and controls data transfers to external storage devices
  - Real-time detection of external drive connections
  - Controlled access to removable media
  - Prevention of unauthorized data copying

- **Machine Learning Classification**: Advanced data sensitivity analysis
  - Pattern-based sensitive data detection
  - Content classification and scoring
  - Adaptive learning capabilities

- **Policy Engine**: Customizable security rules and policies
  - Flexible policy configuration
  - Threshold-based sensitivity controls
  - Comprehensive violation logging
  - Policy enforcement actions

## Project Structure

The system is built with a modular architecture:

```
src/
├── core/                 # Core monitoring components
│   ├── clipboard/        # Clipboard monitoring
│   ├── file_monitor/     # File system monitoring
│   ├── email/           # Email monitoring
│   └── device/          # External device monitoring
├── ml/                  # Machine learning components
│   ├── classifiers/     # Data classification models
│   └── behavioral/      # Behavioral analysis
├── policy/              # Policy engine and rules
├── dashboard/           # Web-based monitoring interface
└── utils/               # Common utilities
```

## Setup

1. Install Python 3.8 or higher
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure policies in `config/policies.yaml`
4. Run the system:
   ```bash
   python src/main.py
   ```

## Development

- Python 3.8+
- Uses machine learning for data classification
- Real-time monitoring and alerting
- Modular design for easy extension
