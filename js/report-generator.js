// report-generator.js - Advanced Reporting
// Version 2.1.1

const ReportGenerator = {
    downloadJSON(analysis, fileName) {
        const report = this.generateJSONReport(analysis);
        const jsonString = JSON.stringify(report, null, 2);
        
        const reportFileName = fileName.replace('.json', '') + '_analysis.json';
        Utils.downloadJSON(report, reportFileName);
    },

    downloadHTML(analysis, fileName) {
        const html = this.generateHTMLReport(analysis, fileName);
        const reportFileName = fileName.replace('.json', '') + '_report.html';
        Utils.downloadHTML(html, reportFileName);
    },

    printToPDF(analysis) {
        // Create a new window with the report
        const printWindow = window.open('', '_blank');
        const html = this.generateHTMLReport(analysis, 'PDF Report');
        
        printWindow.document.write(html);
        printWindow.document.close();
        
        // Wait for content to load, then print
        printWindow.onload = function() {
            printWindow.print();
        };
    },

    generateJSONReport(analysis) {
        return {
            metadata: {
                tool: 'C2 Beacon Detector',
                version: '2.1.0',
                timestamp: new Date().toISOString(),
                analyzed_file: analysis.fileName || 'unknown',
                features_enabled: {
                    threat_intel: analysis.threatIntel !== null,
                    machine_learning: analysis.mlPrediction !== null && analysis.mlPrediction.enabled,
                    historical_comparison: typeof HistoryManager !== 'undefined'
                }
            },
            summary: {
                score: analysis.score,
                classification: analysis.classification,
                severity: analysis.severity,
                recommendation: analysis.recommendation
            },
            threat_intelligence: analysis.threatIntel ? {
                ips_checked: analysis.threatIntel.checked,
                matches_found: analysis.threatIntel.matches.length,
                matches: analysis.threatIntel.matches
            } : null,
            machine_learning: analysis.mlPrediction && analysis.mlPrediction.enabled ? {
                ensemble: analysis.mlPrediction.ensemble,
                beacon_classifier: analysis.mlPrediction.beacon,
                anomaly_detector: analysis.mlPrediction.anomaly
            } : null,
            detection_factors: analysis.detectionFactors,
            behavioral_analysis: {
                timing: {
                    mean_interval_ms: analysis.features.meanInterval,
                    median_interval_ms: analysis.features.medianInterval,
                    std_dev_ms: analysis.features.stdDevInterval,
                    jitter: analysis.features.jitter,
                    periodicity: analysis.features.periodicity,
                    entropy: analysis.features.timingEntropy
                },
                payload: {
                    mean_bytes: analysis.features.meanPayload,
                    median_bytes: analysis.features.medianPayload,
                    consistency: analysis.features.payloadConsistency,
                    entropy: analysis.features.payloadEntropy
                },
                network: {
                    unique_destinations: analysis.features.uniqueDestinations,
                    unique_sources: analysis.features.uniqueSources,
                    port_diversity: analysis.features.portDiversity,
                    most_common_port: analysis.features.mostCommonPort
                },
                duration: {
                    total_ms: analysis.features.durationMs,
                    hours: analysis.features.durationHours,
                    connection_count: analysis.features.connectionCount
                }
            },
            framework_signatures: analysis.features.frameworkSignatures || [],
            mitre_attack: analysis.features.mitreAttack || [],
            features: analysis.features
        };
    },

    generateHTMLReport(analysis, fileName) {
        const timestamp = new Date().toLocaleString();
        
        return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>C2 Beacon Detection Report - ${fileName}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a;
            color: #f8fafc;
            padding: 2rem;
            line-height: 1.6;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #1e293b, #0f172a);
            border: 1px solid #334155;
            border-radius: 0.75rem;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        .logo { color: #22d3ee; font-size: 2rem; margin-bottom: 0.5rem; }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .subtitle { color: #94a3b8; font-size: 0.875rem; }
        .section {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .section-title {
            color: #22d3ee;
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            border-bottom: 1px solid #334155;
            padding-bottom: 0.5rem;
        }
        .badge {
            display: inline-block;
            padding: 0.5rem 1.5rem;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 1.125rem;
            margin: 1rem 0;
        }
        .badge-critical { background: #7f1d1d; color: #fecaca; }
        .badge-high { background: #7c2d12; color: #fed7aa; }
        .badge-medium { background: #713f12; color: #fef08a; }
        .badge-info { background: #14532d; color: #bbf7d0; }
        .score-box {
            background: #0f172a;
            border: 2px solid #334155;
            border-radius: 0.5rem;
            padding: 1.5rem;
            text-align: center;
            margin: 1rem 0;
        }
        .score-value {
            font-size: 3rem;
            font-weight: 700;
            color: #22d3ee;
        }
        .grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
        .stat-box {
            background: #0f172a;
            border-radius: 0.5rem;
            padding: 1rem;
        }
        .stat-label { color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem; }
        .stat-value { color: #22d3ee; font-size: 1.25rem; font-weight: 700; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; }
        th { color: #94a3b8; font-weight: 600; }
        td { color: #cbd5e1; }
        .footer {
            text-align: center;
            color: #64748b;
            font-size: 0.875rem;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid #334155;
        }
        @media print {
            body { background: white; color: black; }
            .section { border: 1px solid #ddd; background: white; }
            .header { background: #f8f9fa; color: black; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ C2 Beacon Detector v2.1</div>
            <h1>Incident Response Report</h1>
            <div class="subtitle">
                File: ${fileName}<br>
                Generated: ${timestamp}<br>
                Analysis ID: ${analysis.id || 'N/A'}
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <div class="section-title">Executive Summary</div>
            <div class="score-box">
                <div style="color: #94a3b8; font-size: 0.875rem; margin-bottom: 0.5rem;">THREAT SCORE</div>
                <div class="score-value">${analysis.score}</div>
                <div class="badge ${this.getBadgeClass(analysis.classification)}">${analysis.classification}</div>
            </div>
            <p style="color: #cbd5e1; line-height: 1.8;">
                ${analysis.recommendation}
            </p>
        </div>

        ${analysis.threatIntel && analysis.threatIntel.matches.length > 0 ? `
        <!-- Threat Intelligence -->
        <div class="section">
            <div class="section-title">Threat Intelligence Matches</div>
            <p style="color: #fca5a5; margin-bottom: 1rem;">
                ⚠️ ${analysis.threatIntel.matches.length} known malicious IP(s) detected
            </p>
            ${analysis.threatIntel.matches.map(match => `
                <div style="background: rgba(127, 29, 29, 0.3); border: 1px solid #b91c1c; border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem;">
                    <div style="font-weight: 700; color: #fca5a5; margin-bottom: 0.5rem;">${match.ip}</div>
                    <div style="font-size: 0.875rem; color: #cbd5e1;">
                        <strong>Malware:</strong> ${match.malware}<br>
                        <strong>Source:</strong> ${match.source}<br>
                        <strong>Confidence:</strong> ${match.confidence}%<br>
                        ${match.tags && match.tags.length > 0 ? `<strong>Tags:</strong> ${match.tags.join(', ')}<br>` : ''}
                    </div>
                </div>
            `).join('')}
        </div>
        ` : ''}

        ${analysis.mlPrediction && analysis.mlPrediction.enabled ? `
        <!-- Machine Learning Analysis -->
        <div class="section">
            <div class="section-title">Machine Learning Analysis</div>
            <div class="grid">
                <div class="stat-box">
                    <div class="stat-label">Prediction</div>
                    <div class="stat-value">${analysis.mlPrediction.ensemble.prediction}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Confidence</div>
                    <div class="stat-value">${analysis.mlPrediction.ensemble.confidence}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">ML Score</div>
                    <div class="stat-value">${(analysis.mlPrediction.ensemble.score * 100).toFixed(1)}%</div>
                </div>
            </div>
        </div>
        ` : ''}

        <!-- Detection Factors -->
        <div class="section">
            <div class="section-title">Detection Factors</div>
            <table>
                <thead>
                    <tr>
                        <th>Factor</th>
                        <th>Points</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    ${analysis.detectionFactors.map(factor => `
                        <tr>
                            <td>${factor.factor}</td>
                            <td style="color: ${factor.points < 0 ? '#86efac' : '#fca5a5'}; font-weight: 700;">
                                ${factor.points < 0 ? '' : '+'}${factor.points}
                            </td>
                            <td>${factor.details}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <!-- Network Statistics -->
        <div class="section">
            <div class="section-title">Network Statistics</div>
            <div class="grid">
                <div class="stat-box">
                    <div class="stat-label">Connections</div>
                    <div class="stat-value">${analysis.features.connectionCount}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Duration</div>
                    <div class="stat-value">${Utils.formatDuration(analysis.features.durationMs)}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Destinations</div>
                    <div class="stat-value">${analysis.features.uniqueDestinations}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Avg Interval</div>
                    <div class="stat-value">${Utils.formatDuration(analysis.features.meanInterval)}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Periodicity</div>
                    <div class="stat-value">${(analysis.features.periodicity * 100).toFixed(1)}%</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Jitter</div>
                    <div class="stat-value">${(analysis.features.jitter * 100).toFixed(1)}%</div>
                </div>
            </div>
        </div>

        ${analysis.features.frameworkSignatures && analysis.features.frameworkSignatures.length > 0 ? `
        <!-- Framework Signatures -->
        <div class="section">
            <div class="section-title">Framework Signatures Detected</div>
            ${analysis.features.frameworkSignatures.map(sig => `
                <div style="background: #0f172a; border-radius: 0.5rem; padding: 1rem; margin-bottom: 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <strong style="color: #22d3ee;">${sig.framework}</strong>
                        <span style="background: #1e3a8a; color: #bfdbfe; padding: 0.25rem 0.75rem; border-radius: 0.25rem; font-size: 0.75rem;">
                            ${sig.confidence}
                        </span>
                    </div>
                    <div style="color: #94a3b8; font-size: 0.875rem;">${sig.reason}</div>
                </div>
            `).join('')}
        </div>
        ` : ''}

        ${analysis.features.mitreAttack && analysis.features.mitreAttack.length > 0 ? `
        <!-- MITRE ATT&CK -->
        <div class="section">
            <div class="section-title">MITRE ATT&CK Techniques</div>
            ${analysis.features.mitreAttack.map(tech => `
                <div style="background: #0f172a; border-radius: 0.5rem; padding: 1rem; margin-bottom: 0.75rem;">
                    <div style="font-weight: 700; color: #22d3ee; margin-bottom: 0.5rem;">
                        ${tech.id}: ${tech.name}
                    </div>
                    <div style="color: #94a3b8; font-size: 0.875rem;">${tech.description}</div>
                </div>
            `).join('')}
        </div>
        ` : ''}

        <div class="footer">
            <p>This report was generated by C2 Beacon Detector v2.1</p>
            <p style="margin-top: 0.5rem;">For authorized security analysis only</p>
        </div>
    </div>
</body>
</html>
        `;
    },

    getBadgeClass(classification) {
        const mapping = {
            'CRITICAL': 'badge-critical',
            'SUSPICIOUS': 'badge-high',
            'MONITOR': 'badge-medium',
            'BENIGN': 'badge-info'
        };
        return mapping[classification] || 'badge-info';
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ReportGenerator;
}
