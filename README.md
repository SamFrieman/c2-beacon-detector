# C2 Beacon Detector

**Professional-grade Command & Control beacon detection tool with integrated threat intelligence**

A powerful, client-side network traffic analysis tool that combines behavioral pattern recognition with real-time threat intelligence to identify C2 beaconing activity. Perfect for security analysts, incident responders, and threat hunters.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Threat Intel](https://img.shields.io/badge/Threat%20Intel-ThreatFox-red)](https://threatfox.abuse.ch/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue)](https://attack.mitre.org/)

---

## Features

### Behavioral Analysis
- **Timing Pattern Detection** - Identifies regular beaconing intervals
- **Jitter Analysis** - Calculates timing variance and consistency
- **Periodicity Scoring** - Measures connection regularity
- **Entropy Calculation** - Detects automated patterns
- **Payload Consistency** - Analyzes data size patterns
- **Port Diversity Analysis** - Identifies single-port communications
- **Time-of-Day Patterns** - Detects unusual activity hours

### Threat Intelligence Integration
- **ThreatFox API** - Real-time IOC lookups from Abuse.ch
- **Malicious IP Detection** - Cross-references known C2 infrastructure
- **Malware Family Identification** - Maps IOCs to known threats
- **Confidence Scoring** - Weighted threat assessment
- **Automatic IP Reputation** - Checks all external destinations
- **Cache Optimization** - Reduces API calls with smart caching

### Framework Identification
Detects signatures from popular C2 frameworks:
- **Cobalt Strike** - 60s beacon intervals with low jitter
- **Metasploit/Meterpreter** - 120s beacon patterns
- **PowerShell Empire** - Short intervals with periodicity
- **Sliver** - Consistent payload patterns
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
- **Export Reports** - Professional JSON reports for IR

---

## Quick Start

### Online Demo
Visit the [live demo](https://your-github-pages-url.github.io/c2-beacon-detector/) to try it immediately.

### Local Installation

```bash
# Clone the repository
git clone https://github.com/samfrieman/c2-beacon-detector.git
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
- **Cobalt Strike Sample** - High-confidence C2 traffic
- **Metasploit Sample** - Medium-confidence beaconing
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

| Field | Alternatives | Required |
|-------|-------------|----------|
| `timestamp` | `time`, `ts`, `epoch` | ✅ Yes |
| `bytes` | `size`, `length` | ❌ No |
| `dest_ip` | `dst`, `destination`, `dst_ip` | ✅ Yes |
| `src_ip` | `src`, `source` | ❌ No |
| `dest_port` | `dport` | ❌ No |
| `src_port` | `sport` | ❌ No |

### Minimum Requirements
- At least **2 connections** required
- Must include **timestamp** field
- Timestamp can be Unix epoch (seconds or milliseconds)

---

## Architecture

The project uses a modular design for maintainability and extensibility:

```
c2-beacon-detector/
├── index.html          # Main HTML structure
├── styles.css          # All styling
├── utils.js            # Utility functions
├── threat-intel.js     # ThreatFox API integration
├── analyzer.js         # Behavioral analysis engine
├── detector.js         # Detection & scoring logic
├── ui.js               # UI rendering controller
└── app.js              # Main application controller
```

### Module Responsibilities

#### `utils.js`
- JSON parsing and validation
- Statistical calculations
- IP extraction and filtering
- Data formatting utilities
- Sample data generation

#### `threat-intel.js`
- ThreatFox API client
- IOC lookups and caching
- Malware family mapping
- IP reputation checking
- Rate limiting

#### `analyzer.js`
- Feature extraction
- Entropy calculation
- Pattern detection
- Framework identification
- MITRE ATT&CK mapping

#### `detector.js`
- Scoring algorithm
- Threat classification
- Report generation
- Multi-factor assessment

#### `ui.js`
- Results rendering
- Error handling
- Loading states
- Dynamic updates

#### `app.js`
- Application lifecycle
- Event handlers
- State management
- Workflow coordination

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
│ Features             │
│ • Timing patterns    │
│ • Payload sizes      │
│ • Network metadata   │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Threat Intelligence  │
│ Lookup               │
│ • Check IPs          │
│ • Match IOCs         │
│ • Identify malware   │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Detection Engine     │
│ • Score indicators   │
│ • Map MITRE tactics  │
│ • Classify threat    │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Generate Report      │
│ • Visualize results  │
│ • Export JSON        │
└────────────────────────┘
```

### Detection Scoring

The tool uses a multi-factor scoring system (0-100):

| Score Range | Classification | Action Required |
|-------------|---------------|-----------------|
| 80-100 | **CRITICAL** | Immediate isolation & IR escalation |
| 65-79 | **SUSPICIOUS** | Urgent investigation required |
| 45-64 | **MONITOR** | Enhanced monitoring recommended |
| 0-44 | **BENIGN** | Continue normal operations |

### Scoring Factors

**High Impact (+30-45 points)**
- Threat intel IOC match
- Extreme periodicity (>80%)
- Extremely low jitter (<8%)

**Medium Impact (+15-25 points)**
- Known C2 signatures
- Consistent payloads (>90%)
- Sustained beaconing (>2 hours)

**Low Impact (+8-15 points)**
- Single destination patterns
- Common C2 intervals (30-300s)
- Low entropy patterns

**Benign Indicators (-10-25 points)**
- High timing variance
- Multiple destinations
- Very short intervals

---

## Example Output

### Console Output
```
Initializing C2 Beacon Detector...
Threat intelligence feeds loaded successfully
Found 2 threat intel matches
Analysis complete: CRITICAL (Score: 87)
```

### Export Report Structure
```json
{
  "metadata": {
    "tool": "C2 Beacon Detector",
    "version": "2.0.0",
    "timestamp": "2024-01-11T10:30:00Z",
    "analyzed_file": "traffic_capture.json"
  },
  "summary": {
    "score": 87,
    "classification": "CRITICAL",
    "severity": "critical",
    "recommendation": "🚨 IMMEDIATE ACTION: High confidence C2 detected..."
  },
  "threat_intelligence": {
    "matches": [...],
    "total_iocs_matched": 2
  },
  "behavioral_analysis": {
    "frameworks": [...],
    "mitre_techniques": [...],
    "detection_factors": [...]
  },
  "features": {...}
}
```

---

## Use Cases

### Incident Response
- Quickly triage suspected C2 traffic
- Generate evidence for investigations
- Correlate with threat intelligence
- Export findings for documentation

### Threat Hunting
- Proactive beaconing detection
- Pattern baseline establishment
- Framework fingerprinting
- IOC enrichment

### Security Operations
- PCAP analysis
- SIEM alert validation
- Network monitoring
- Training and education

### Red Team / Purple Team
- Validate C2 evasion techniques
- Test detection capabilities
- Improve defensive posture
- Assess tool effectiveness

---

## ⚙️ Configuration

### ThreatFox API Settings
Located in `threat-intel.js`:

```javascript
config: {
    threatfoxAPI: 'https://threatfox-api.abuse.ch/api/v1/',
    cacheExpiry: 3600000,  // 1 hour cache
    maxIPs: 20             // Max IPs to check per analysis
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
```

### Adding New Features

1. **New Detection Pattern**
   - Add logic to `analyzer.js`
   - Update scoring in `detector.js`
   - Add UI elements in `ui.js`

2. **New Threat Intel Source**
   - Extend `threat-intel.js`
   - Add API integration
   - Update status dashboard

3. **New Export Format**
   - Modify `detector.js::generateReport()`
   - Add export button in UI
   - Implement new format handler

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

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Sam Frieman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## Acknowledgments

- **Abuse.ch** - ThreatFox API and IOC data
- **MITRE Corporation** - ATT&CK Framework
- **Security Community** - Research and techniques
- **Font Awesome** - Icons

---

## Disclaimer

**FOR AUTHORIZED SECURITY ANALYSIS ONLY**

This tool is intended for legitimate security research, incident response, and authorized penetration testing. Users are responsible for ensuring they have proper authorization before analyzing network traffic. Unauthorized interception or analysis of network communications may be illegal in your jurisdiction.

The authors assume no liability for misuse of this tool.

---

## Support & Contact

- **Issues**: [GitHub Issues](https://github.com/samfrieman/c2-beacon-detector/issues)
- **Email**: security@example.com
- **Twitter**: [@samfrieman](https://twitter.com/samfrieman)

---

## Roadmap

### v2.1 (Planned)
- [ ] Multiple threat intel source integration
- [ ] Machine learning model integration
- [ ] Advanced reporting (PDF, HTML)
- [ ] Historical analysis comparison
- [ ] Custom detection rule engine

### v2.2 (Future)
- [ ] Live packet capture support
- [ ] Zeek/Suricata log parsing
- [ ] Collaborative threat hunting
- [ ] API for automation
- [ ] Docker container deployment

---

## Further Reading

- [Command and Control Matrix](https://attack.mitre.org/tactics/TA0011/)
- [ThreatFox Documentation](https://threatfox.abuse.ch/)
- [Cobalt Strike Beacon Analysis](https://www.cobaltstrike.com/)
- [Network Beaconing Detection Techniques](https://www.sans.org/)

---

<div align="center">

**Built with for the security community**

Star this repo if you find it useful!

</div>
