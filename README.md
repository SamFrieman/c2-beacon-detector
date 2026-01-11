# C2 Beacon Detector v2.1

**Professional-grade Command & Control beacon detection with Machine Learning and Multi-Source Threat Intelligence**

A powerful, client-side network traffic analysis tool that combines behavioral pattern recognition, machine learning, and real-time threat intelligence from multiple sources to identify C2 beaconing activity. Perfect for security analysts, incident responders, and threat hunters.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)](https://github.com/SamFrieman/c2-beacon-detector)
[![Threat Intel](https://img.shields.io/badge/Threat%20Intel-ThreatFox-red)](https://threatfox.abuse.ch/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue)](https://attack.mitre.org/)

---

## What's New in v2.1

### Multi-Source Threat Intelligence
- **ThreatFox Integration** - Real-time IOC lookups from Abuse.ch
- **Custom Detection Rules** - Add your own IP/CIDR-based rules
- **Combined Scoring** - Weighted confidence across multiple sources
- **Rule Management** - Import/export custom rule sets

### Machine Learning Integration
- **Beacon Classifier** - Random Forest-based detection model
- **Anomaly Detection** - Isolation Forest for outlier identification
- **Ensemble Predictions** - Combined model outputs for higher accuracy
- **Adaptive Learning** - Models improve with historical data

### Advanced Reporting
- **HTML Reports** - Professional incident response documents
- **PDF Export** - Print-ready analysis reports
- **Enhanced JSON** - Comprehensive structured data export
- **Executive Summaries** - High-level overviews for management

### Historical Analysis
- **Automatic Tracking** - Stores up to 100 analyses locally
- **Percentile Comparison** - "Scored higher than 90% of past analyses"
- **Similar Pattern Detection** - Find analyses with similar characteristics
- **Trend Analysis** - View patterns over time periods
- **CSV/JSON Export** - Export historical data for external analysis

### Custom Rule Engine
- **IP-based Rules** - Match specific IP addresses
- **CIDR Ranges** - Support for network ranges (e.g., 10.0.0.0/8)
- **Confidence Scoring** - Configurable threat levels
- **Tags & Metadata** - Organize and categorize rules
- **Persistent Storage** - Rules saved across sessions

---

## Core Features

### Behavioral Analysis
- **Timing Pattern Detection** - Identifies regular beaconing intervals
- **Jitter Analysis** - Calculates timing variance and consistency
- **Periodicity Scoring** - Measures connection regularity
- **Entropy Calculation** - Detects automated patterns
- **Payload Consistency** - Analyzes data size patterns
- **Port Diversity Analysis** - Identifies single-port communications
- **Time-of-Day Patterns** - Detects unusual activity hours

### Framework Identification
Detects signatures from popular C2 frameworks:
- **Cobalt Strike** - 60s beacon intervals with low jitter
- **Metasploit/Meterpreter** - 120s beacon patterns
- **PowerShell Empire** - Short intervals with periodicity
- **Sliver** - Consistent payload patterns
- **Covenant** - .NET C2 framework signatures
- **Custom C2s** - Generic pattern detection

### MITRE ATT&CK Mapping
- **T1071** - Application Layer Protocol
- **T1573** - Encrypted Channel
- **T1001** - Data Obfuscation
- Automatic technique mapping based on detected behaviors

### Privacy & Security
- **100% Client-Side** - No data leaves your browser
- **No Data Upload** - All processing done locally
- **Private IP Filtering** - Skips RFC1918 addresses
- **Open Source** - Full transparency
- **LocalStorage Only** - Data stays on your machine

---

## Quick Start

### Online Demo
Visit the [live demo](https://samfrieman.github.io/c2-beacon-detector/) to try it immediately.

### Local Installation

```bash
# Clone the repository
git clone https://github.com/SamFrieman/c2-beacon-detector.git
cd c2-beacon-detector

# Serve locally (Python 3)
python -m http.server 8000

# Or use Node.js
npx http-server -p 8000

# Open in browser
open http://localhost:8000
```

### Using Sample Data
Click any of the sample buttons to see the tool in action:
- **Cobalt Strike Sample** - High-confidence C2 traffic with known IOC
- **Metasploit Sample** - Medium-confidence beaconing pattern
- **Benign Traffic Sample** - Normal network activity

---

## Input Format

### Expected JSON Structure

```json
{
  "connections": [
    {
      "timestamp": 1704646800000,
      "bytes": 1024,
      "dest_ip": "192.168.1.100",
      "src_ip": "10.0.0.50",
      "src_port": 49152,
      "dest_port": 443
    }
  ]
}
```

### Supported Field Names

| Field | Alternatives | Required | Description |
|-------|-------------|----------|-------------|
| `timestamp` | `time`, `ts`, `epoch` | ✅ Yes | Unix timestamp (ms or seconds) |
| `bytes` | `size`, `length` | ❌ No | Payload size in bytes |
| `dest_ip` | `dst`, `destination`, `dst_ip` | ✅ Yes | Destination IP address |
| `src_ip` | `src`, `source` | ❌ No | Source IP address |
| `dest_port` | `dport` | ❌ No | Destination port number |
| `src_port` | `sport` | ❌ No | Source port number |

### Minimum Requirements
- At least **2 connections** required
- Must include **timestamp** field
- Timestamp can be Unix epoch (seconds or milliseconds)

---

## Architecture

The project uses a modular design for maintainability and extensibility:

```
c2-beacon-detector/
├── index.html              # Main HTML structure
├── styles.css              # All styling
├── utils.js                # Utility functions
├── threat-intel.js         # Multi-source threat intelligence
├── ml-detector.js          # Machine learning models
├── history-manager.js      # Historical analysis tracking
├── report-generator.js     # HTML/PDF report generation
├── analyzer.js             # Behavioral analysis engine
├── detector.js             # Detection & scoring logic
├── ui.js                   # UI rendering controller
└── app.js                  # Main application controller
```

### Module Responsibilities

#### `utils.js` - Core Utilities
- JSON parsing and validation
- Statistical calculations (mean, median, std dev)
- IP extraction and filtering (RFC1918 detection)
- Data formatting (bytes, timestamps, durations)
- Sample data generation

#### `threat-intel.js` - Multi-Source Threat Intelligence
- ThreatFox API client
- Custom rule management (IP/CIDR)
- Multi-source IOC lookups
- Combined confidence scoring
- Malware family mapping
- Rule import/export

#### `ml-detector.js` - Machine Learning
- Beacon classification model
- Anomaly detection (Isolation Forest)
- Ensemble predictions
- Feature normalization
- Model training on historical data
- Prediction explanation

#### `history-manager.js` - Historical Analysis
- Analysis storage (up to 100 records)
- Percentile calculations
- Similar pattern detection
- Trend analysis
- CSV/JSON export
- History import

#### `report-generator.js` - Advanced Reporting
- HTML report generation
- PDF export (via print)
- Enhanced JSON format
- Professional IR documentation
- Executive summaries

#### `analyzer.js` - Behavioral Analysis
- Feature extraction (25+ features)
- Entropy calculation
- Pattern detection
- Framework identification
- MITRE ATT&CK mapping
- Port/time analysis

#### `detector.js` - Detection Engine
- Multi-factor scoring algorithm
- Threat classification
- IOC prioritization
- Report generation
- Benign indicator handling

#### `ui.js` - UI Controller
- Results rendering
- Error handling
- Loading states
- Dynamic updates
- Multi-format export buttons

#### `app.js` - Application Controller
- Module initialization
- Event handlers
- State management
- Workflow coordination
- Keyboard shortcuts

---

## How It Works

### Analysis Pipeline

```
┌─────────────┐
│ Upload JSON │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ Validate Format │
└──────┬──────────┘
       │
       ▼
┌──────────────────────┐
│ Extract Behavioral   │
│ Features (25+)       │
│ • Timing patterns    │
│ • Payload analysis   │
│ • Network metadata   │
│ • Entropy & jitter   │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Multi-Source Threat  │
│ Intelligence         │
│ • ThreatFox API      │
│ • Custom rules       │
│ • CIDR matching      │
│ • Combined scoring   │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Machine Learning     │
│ Prediction           │
│ • Beacon classifier  │
│ • Anomaly detector   │
│ • Ensemble model     │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Detection Engine     │
│ • Multi-factor score │
│ • MITRE mapping      │
│ • Classification     │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Historical Compare   │
│ • Percentile rank    │
│ • Similar patterns   │
│ • Trend analysis     │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Generate Reports     │
│ • HTML/PDF/JSON      │
│ • Save to history    │
│ • Update ML models   │
└────────────────────────┘
```

### Detection Scoring

The tool uses a multi-factor scoring system (0-100):

| Score Range | Classification | ML Prediction | Action Required |
|-------------|---------------|---------------|-----------------|
| 80-100 | **CRITICAL** | Malicious (High Conf) | Immediate isolation & IR escalation |
| 65-79 | **SUSPICIOUS** | Malicious (Medium) | Urgent investigation required |
| 45-64 | **MONITOR** | Suspicious | Enhanced monitoring recommended |
| 0-44 | **BENIGN** | Benign | Continue normal operations |

### Scoring Factors

**Threat Intelligence (+45-70 points)**
- IOC match from ThreatFox
- Multiple source confirmation
- High confidence malware family
- Custom rule matches

**Machine Learning (+20-35 points)**
- ML ensemble: Malicious prediction
- High anomaly score
- Multiple anomaly factors

**Periodicity (+15-35 points)**
- Extreme periodicity (>80%)
- Strong periodicity (>70%)
- Notable periodicity (>60%)

**Jitter (+10-30 points)**
- Extremely low jitter (<8%)
- Low jitter (<15%)
- Consistent timing (<25%)

**Payload Consistency (+15-20 points)**
- Very consistent sizes (>90%)
- Consistent payloads (>80%)

**Known C2 Signatures (+18-20 points)**
- 60s Cobalt Strike beacon
- 120s Metasploit pattern
- Empire/Sliver signatures

**Persistence (+12-15 points)**
- Sustained beaconing (>2 hours)
- Extended patterns (>1 hour)

**Network Patterns (+10-12 points)**
- Single destination IP
- Low port diversity
- Low entropy patterns

**Benign Indicators (-10 to -25 points)**
- High timing variance
- Multiple destinations
- Very short intervals
- High time diversity

---

## Example Output

### Console Output
```
Initializing C2 Beacon Detector v2.1...
✓ ThreatFox: Loaded 1247 IOCs
✓ ML models initialized
✓ Loaded 23 historical analyses
✓ All systems initialized
  - Threat Intel: 2 source(s) active
  - ML Models: Enabled
  - History: 23 record(s)

Found 2 threat intel matches
ML prediction: malicious
Analysis complete: CRITICAL (Score: 92)
```

### HTML Report Preview
The HTML report includes:
- Executive summary with threat score
- Threat intelligence matches (all sources)
- Machine learning analysis results
- Network data statistics
- Detection factors breakdown
- MITRE ATT&CK technique mapping
- Extracted features table
- Professional styling for printing

### Export Report Structure (JSON)
```json
{
  "metadata": {
    "tool": "C2 Beacon Detector",
    "version": "2.1.0",
    "timestamp": "2024-01-11T10:30:00Z",
    "analyzed_file": "traffic_capture.json",
    "features_enabled": {
      "threat_intel": true,
      "machine_learning": true,
      "historical_comparison": true
    }
  },
  "summary": {
    "score": 92,
    "classification": "CRITICAL",
    "severity": "critical",
    "recommendation": "🚨 IMMEDIATE ACTION..."
  },
  "threat_intelligence": {
    "matches": [...],
    "total_iocs_matched": 2,
    "sources_used": ["ThreatFox", "Custom Rules"]
  },
  "machine_learning": {
    "ensemble": {
      "prediction": "malicious",
      "confidence": "high",
      "score": 0.87
    }
  },
  "behavioral_analysis": {...},
  "network_data": {...},
  "features": {...}
}
```

---

## Use Cases

### Incident Response
- Quickly triage suspected C2 traffic
- Generate professional reports for documentation
- Correlate with multiple threat intelligence sources
- Track analysis history for investigation timeline
- Export findings in multiple formats

### Threat Hunting
- Proactive beaconing detection
- Pattern baseline establishment
- Framework fingerprinting
- IOC enrichment from multiple sources
- Historical trend analysis

### Security Operations
- PCAP analysis
- SIEM alert validation
- Network monitoring
- Custom rule deployment
- Training and education

### Red Team / Purple Team
- Validate C2 evasion techniques
- Test detection capabilities
- Improve defensive posture
- Assess tool effectiveness
- Document exercise results

---

## Configuration

### Threat Intelligence Settings
Located in `threat-intel.js`:

```javascript
config: {
    threatfoxAPI: 'https://threatfox-api.abuse.ch/api/v1/',
    cacheExpiry: 3600000,  // 1 hour cache
    maxIPs: 20,            // Max IPs to check per analysis
    enabledSources: {
        threatfox: true,
        customRules: true
    }
}
```

### Machine Learning Settings
Located in `ml-detector.js`:

```javascript
config: {
    enabled: true,
    confidenceThreshold: 0.65,
    useEnsemble: true
}
```

### Detection Thresholds
Located in `detector.js` - adjust scoring as needed:

```javascript
// Periodicity thresholds
if (features.periodicity > 0.80) score += 35;  // CRITICAL
if (features.periodicity > 0.70) score += 25;  // HIGH
if (features.periodicity > 0.60) score += 15;  // MODERATE
```

### History Settings
Located in `history-manager.js`:

```javascript
maxHistorySize: 100  // Maximum stored analyses
```

---

## Advanced Features

### Custom Detection Rules

Add your own IOCs via the UI:

```javascript
// Add IP-based rule
ThreatIntel.addCustomRule({
    type: 'ip',
    value: '192.168.1.100',
    malware: 'Custom C2',
    confidence: 85,
    threat_type: 'c2',
    tags: ['internal', 'suspected'],
    description: 'Suspected internal C2 server'
});

// Add CIDR range rule
ThreatIntel.addCustomRule({
    type: 'cidr',
    value: '10.0.0.0/8',
    malware: 'Internal Range',
    confidence: 70,
    tags: ['network-scan']
});
```

### Export Custom Rules

```javascript
// Export rules to JSON
const rulesJSON = ThreatIntel.exportRules();
// Save to file or share with team

// Import rules from JSON
ThreatIntel.importRules(rulesJSON);
```

### Historical Analysis

```javascript
// View recent history
const history = HistoryManager.getHistory(20);

// Get trend analysis
const trends = HistoryManager.getTrends(7); // Last 7 days

// Export history as CSV
const csv = HistoryManager.exportHistory('csv');

// Compare current with historical
const comparison = HistoryManager.compareWithHistory(currentAnalysis);
```

### Report Generation

```javascript
// Download JSON report
downloadReport('json');

// Download HTML report
downloadReport('html');

// Print to PDF
downloadReport('pdf');
```

### Keyboard Shortcuts

- **Ctrl+H** / **Cmd+H** - View analysis history
- **Ctrl+E** / **Cmd+E** - Export current report (JSON)

---

## Development

### Prerequisites
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Web server for local development
- Internet connection (for threat intel lookups)

### Local Development
```bash
# Install a simple web server
npm install -g http-server

# Run the server
http-server -p 8080

# Open in browser
open http://localhost:8080
```

### Testing
```bash
# Test with sample data
# Click "Cobalt Strike Sample" button in the UI

# Test with your own JSON
# Drag and drop a properly formatted JSON file

# Test custom rules
# Add a custom IP rule and re-analyze
```

### Adding New Features

1. **New Threat Intel Source**
   ```javascript
   // In threat-intel.js
   async lookupNewSource(ip) {
       const response = await fetch(`https://api.example.com/lookup/${ip}`);
       return await response.json();
   }
   ```

2. **New ML Model**
   ```javascript
   // In ml-detector.js
   createNewModel() {
       return {
           predict: (features) => {
               // Your model logic
               return { score: 0.85, prediction: 'malicious' };
           }
       };
   }
   ```

3. **New Export Format**
   ```javascript
   // In report-generator.js
   generateMarkdown(analysis, fileName, connections) {
       // Generate markdown format
   }
   ```

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Code Style
- Use descriptive variable names
- Comment complex logic
- Follow existing patterns
- Keep functions focused and small
- Update documentation

### Pull Request Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How has this been tested?

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings generated
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Sam Frieman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## Acknowledgments

- **Abuse.ch** - ThreatFox API and IOC data
- **MITRE Corporation** - ATT&CK Framework
- **Security Community** - Research and threat intelligence
- **Font Awesome** - Icon library
- **Open Source Contributors** - Community support

---

## Disclaimer

**FOR AUTHORIZED SECURITY ANALYSIS ONLY**

This tool is intended for legitimate security research, incident response, and authorized penetration testing. Users are responsible for ensuring they have proper authorization before analyzing network traffic. Unauthorized interception or analysis of network communications may be illegal in your jurisdiction.

The authors assume no liability for misuse of this tool.

---

## Support & Contact

- **Issues**: [GitHub Issues](https://github.com/SamFrieman/c2-beacon-detector/issues)
- **Discussions**: [GitHub Discussions](https://github.com/SamFrieman/c2-beacon-detector/discussions)
- **Security**: Report security vulnerabilities privately

---

## Roadmap

### v2.1 (Current)
- [x] Multiple threat intel source integration
- [x] Machine learning model integration
- [x] Advanced reporting (PDF, HTML)
- [x] Historical analysis comparison
- [x] Custom detection rule engine

### v2.2 (Planned)
- [ ] Live packet capture support (WebRTC)
- [ ] Zeek/Suricata log parsing
- [ ] Collaborative threat hunting features
- [ ] REST API for automation
- [ ] Docker container deployment
- [ ] Advanced ML models (neural networks)
- [ ] Real-time monitoring dashboard

### v3.0 (Future)
- [ ] Multi-session correlation
- [ ] Threat actor attribution
- [ ] Automated playbook responses
- [ ] Integration with SIEM platforms
- [ ] Mobile app version
- [ ] Cloud-based analysis option (opt-in)

---

## Further Reading

### C2 Detection Resources
- [MITRE ATT&CK - Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [ThreatFox Documentation](https://threatfox.abuse.ch/)
- [Cobalt Strike Beacon Analysis](https://www.cobaltstrike.com/)
- [Network Beaconing Detection](https://www.sans.org/white-papers/)

### Machine Learning in Security
- [Anomaly Detection in Network Traffic](https://arxiv.org/abs/1901.03407)
- [ML for Cybersecurity](https://www.microsoft.com/security/blog/)

### Threat Intelligence
- [OSINT Framework](https://osintframework.com/)
- [Abuse.ch Projects](https://abuse.ch/)

---

## Statistics

![GitHub stars](https://img.shields.io/github/stars/SamFrieman/c2-beacon-detector?style=social)
![GitHub forks](https://img.shields.io/github/forks/SamFrieman/c2-beacon-detector?style=social)
![GitHub issues](https://img.shields.io/github/issues/SamFrieman/c2-beacon-detector)
![GitHub pull requests](https://img.shields.io/github/issues-pr/SamFrieman/c2-beacon-detector)

---

<div align="center">

**Built with ❤️ for the security community**

⭐ **Star this repo if you find it useful!** ⭐

[Report Bug](https://github.com/SamFrieman/c2-beacon-detector/issues) • [Request Feature](https://github.com/SamFrieman/c2-beacon-detector/issues) • [Documentation](https://github.com/SamFrieman/c2-beacon-detector/wiki)

---

**Version 2.1.0** | Released January 2025

</div>
