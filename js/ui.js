// ui.js - UI Rendering Controller
// Version 2.1.1

const UI = {
    renderResults(analysis, connections, fileName) {
        let html = '<div class="card fade-in">';

        // Header with score badge
        html += this.renderHeader(analysis, fileName);

        // Progress bar
        html += this.renderProgressBar(analysis.score, analysis.classification);

        // Recommendation
        html += this.renderRecommendation(analysis);

        html += '</div>';

        // Threat Intelligence Section
        if (analysis.threatIntel && analysis.threatIntel.matches.length > 0) {
            html += this.renderThreatIntel(analysis.threatIntel);
        }

        // ML Prediction Section
        if (analysis.mlPrediction && analysis.mlPrediction.enabled) {
            html += this.renderMLPrediction(analysis.mlPrediction);
        }

        // Detection Factors
        html += this.renderDetectionFactors(analysis.detectionFactors);

        // Framework Signatures
        if (analysis.features.frameworkSignatures && analysis.features.frameworkSignatures.length > 0) {
            html += this.renderFrameworkSignatures(analysis.features.frameworkSignatures);
        }

        // MITRE ATT&CK
        if (analysis.features.mitreAttack && analysis.features.mitreAttack.length > 0) {
            html += this.renderMITRE(analysis.features.mitreAttack);
        }

        // Network Data Stats
        html += this.renderNetworkStats(analysis.features, connections);

        // Key Features
        html += this.renderFeatures(analysis.features);

        // Export Buttons
        html += this.renderExportButtons();

        return html;
    },

    renderHeader(analysis, fileName) {
        const badgeClass = this.getBadgeClass(analysis.classification);
        
        return `
            <div class="result-header">
                <div>
                    <h2>Analysis Results</h2>
                    ${fileName ? `<p style="color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem;">
                        <i class="fas fa-file-code"></i> ${fileName}
                    </p>` : ''}
                </div>
                <div class="badge-group">
                    <span class="badge ${badgeClass}">${analysis.classification}</span>
                </div>
            </div>
        `;
    },

    renderProgressBar(score, classification) {
        const progressClass = this.getProgressClass(classification);
        
        return `
            <div class="progress-section">
                <div class="progress-header">
                    <span class="progress-label">Threat Score</span>
                    <span class="progress-value" style="color: ${this.getScoreColor(score)}">${score}</span>
                </div>
                <div class="progress-bg">
                    <div class="progress-bar ${progressClass}" style="width: ${score}%"></div>
                </div>
            </div>
        `;
    },

    renderRecommendation(analysis) {
        const iconMap = {
            'CRITICAL': '🚨',
            'SUSPICIOUS': '⚠️',
            'MONITOR': '👁️',
            'BENIGN': '✅'
        };

        const icon = iconMap[analysis.classification] || 'ℹ️';

        return `
            <div class="recommendation">
                <h3>
                    ${icon} Recommendation
                </h3>
                <p>${analysis.recommendation}</p>
            </div>
        `;
    },

    renderThreatIntel(threatIntel) {
        let html = '<div class="card fade-in">';
        html += '<div class="card-header">';
        html += '<i class="fas fa-shield-virus icon-cyan"></i>';
        html += '<span>Threat Intelligence Matches</span>';
        html += '</div>';

        threatIntel.matches.forEach(match => {
            html += `
                <div class="threat-match">
                    <div class="threat-match-header">
                        <div class="threat-match-title">
                            <i class="fas fa-exclamation-triangle"></i>
                            <span>${match.ip}</span>
                        </div>
                        <span class="threat-tag">${match.source}</span>
                    </div>
                    <div class="threat-details">
                        <div class="threat-detail">
                            <span class="threat-detail-label">Malware:</span>
                            <span class="threat-detail-value">${match.malware}</span>
                        </div>
                        <div class="threat-detail">
                            <span class="threat-detail-label">Threat Type:</span>
                            <span class="threat-detail-value">${match.threat_type}</span>
                        </div>
                        <div class="threat-detail">
                            <span class="threat-detail-label">Confidence:</span>
                            <span class="threat-detail-value">${match.confidence}%</span>
                        </div>
                        ${match.tags && match.tags.length > 0 ? `
                        <div class="threat-detail">
                            <span class="threat-detail-label">Tags:</span>
                            <span class="threat-detail-value">${match.tags.join(', ')}</span>
                        </div>
                        ` : ''}
                        ${match.first_seen ? `
                        <div class="threat-detail">
                            <span class="threat-detail-label">First Seen:</span>
                            <span class="threat-detail-value">${match.first_seen}</span>
                        </div>
                        ` : ''}
                    </div>
                </div>
            `;
        });

        html += '</div>';
        return html;
    },

    renderMLPrediction(mlPrediction) {
        const ensemble = mlPrediction.ensemble;
        const isPredictionMalicious = ensemble.prediction === 'malicious';
        
        let html = '<div class="card fade-in">';
        html += '<div class="card-header">';
        html += '<i class="fas fa-brain icon-cyan"></i>';
        html += '<span>Machine Learning Analysis</span>';
        html += '</div>';

        html += `
            <div style="background: rgba(30, 41, 59, 0.5); border-radius: 0.5rem; padding: 1.5rem;">
                <div style="display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
                    <div>
                        <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 0.25rem;">
                            Ensemble Prediction
                        </div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: ${isPredictionMalicious ? '#fca5a5' : '#86efac'};">
                            ${ensemble.prediction}
                        </div>
                    </div>
                    <div>
                        <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 0.25rem;">
                            Confidence
                        </div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: #22d3ee;">
                            ${ensemble.confidence}
                        </div>
                    </div>
                    <div>
                        <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 0.25rem;">
                            ML Score
                        </div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: #22d3ee;">
                            ${(ensemble.score * 100).toFixed(1)}%
                        </div>
                    </div>
                </div>

                ${ensemble.indicators && ensemble.indicators.length > 0 ? `
                <div style="margin-top: 1.5rem;">
                    <div style="font-size: 0.875rem; font-weight: 600; color: #cbd5e1; margin-bottom: 0.75rem;">
                        Key Indicators:
                    </div>
                    <ul style="font-size: 0.875rem; color: #94a3b8; margin-left: 1.5rem;">
                        ${ensemble.indicators.map(ind => `<li>${ind}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}
            </div>
        `;

        html += '</div>';
        return html;
    },

    renderDetectionFactors(factors) {
        let html = '<div class="card fade-in">';
        html += '<div class="card-header">';
        html += '<i class="fas fa-list-check icon-cyan"></i>';
        html += '<span>Detection Factors</span>';
        html += '</div>';

        html += '<div class="factors-list">';
        factors.forEach(factor => {
            const isNegative = factor.points < 0;
            const color = isNegative ? '#86efac' : factor.points >= 20 ? '#fca5a5' : '#fef08a';
            
            html += `
                <div class="factor-item">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.5rem;">
                        <strong style="color: #f8fafc;">${factor.factor}</strong>
                        <span style="color: ${color}; font-weight: 700; font-size: 1.125rem;">
                            ${isNegative ? '' : '+'}${factor.points}
                        </span>
                    </div>
                    <div style="font-size: 0.875rem; color: #94a3b8;">
                        ${factor.details}
                    </div>
                </div>
            `;
        });
        html += '</div>';

        html += '</div>';
        return html;
    },

    renderFrameworkSignatures(signatures) {
        let html = '<div class="card fade-in">';
        html += '<div class="card-header">';
        html += '<i class="fas fa-fingerprint icon-cyan"></i>';
        html += '<span>Framework Signatures</span>';
        html += '</div>';

        html += '<div class="grid grid-2">';
        signatures.forEach(sig => {
            const badgeClass = `confidence-${sig.confidence}`;
            
            html += `
                <div class="framework-card">
                    <div class="framework-header">
                        <div class="framework-name">${sig.framework}</div>
                        <span class="confidence-badge ${badgeClass}">${sig.confidence}</span>
                    </div>
                    <div class="framework-reason">${sig.reason}</div>
                    ${sig.indicators ? `
                    <div style="margin-top: 0.75rem; font-size: 0.75rem; color: #64748b;">
                        ${sig.indicators.map(ind => `<div>• ${ind}</div>`).join('')}
                    </div>
                    ` : ''}
                </div>
            `;
        });
        html += '</div>';

        html += '</div>';
        return html;
    },

    renderMITRE(techniques) {
        let html = '<div class="card fade-in">';
        html += '<div class="card-header">';
        html += '<i class="fas fa-crosshairs icon-cyan"></i>';
        html += '<span>MITRE ATT&CK Techniques</span>';
        html += '</div>';

        html += '<div class="grid grid-2">';
        techniques.forEach(tech => {
            html += `
                <div style="background: rgba(30, 41, 59, 0.5); border-radius: 0.5rem; padding: 1rem;">
                    <div style="font-weight: 700; color: #22d3ee; margin-bottom: 0.5rem;">
                        ${tech.id}: ${tech.name}
                    </div>
                    <div style="font-size: 0.875rem; color: #94a3b8; margin-bottom: 0.5rem;">
                        ${tech.description}
                    </div>
                    <div style="font-size: 0.75rem; color: #64748b;">
                        Confidence: ${tech.confidence}
                    </div>
                </div>
            `;
        });
        html += '</div>';

        html += '</div>';
        return html;
    },

    renderNetworkStats(features, connections) {
        let html = '<div class="card fade-in">';
        html += '<div class="card-header">';
        html += '<i class="fas fa-network-wired icon-cyan"></i>';
        html += '<span>Network Data Statistics</span>';
        html += '</div>';

        html += '<div class="grid grid-4">';
        
        const stats = [
            { label: 'Connections', value: features.connectionCount },
            { label: 'Duration', value: Utils.formatDuration(features.durationMs) },
            { label: 'Unique Destinations', value: features.uniqueDestinations },
            { label: 'Avg Interval', value: Utils.formatDuration(features.meanInterval) },
            { label: 'Periodicity', value: (features.periodicity * 100).toFixed(1) + '%' },
            { label: 'Jitter', value: (features.jitter * 100).toFixed(1) + '%' },
            { label: 'Avg Payload', value: Utils.formatBytes(features.meanPayload) },
            { label: 'Most Common Port', value: features.mostCommonPort || 'N/A' }
        ];

        stats.forEach(stat => {
            html += `
                <div class="feature-card">
                    <div class="feature-label">${stat.label}</div>
                    <div class="feature-value">${stat.value}</div>
                </div>
            `;
        });

        html += '</div>';
        html += '</div>';
        return html;
    },

    renderFeatures(features) {
        let html = '<div class="card fade-in">';
        html += '<div class="card-header">';
        html += '<i class="fas fa-chart-line icon-cyan"></i>';
        html += '<span>Extracted Features</span>';
        html += '</div>';

        html += '<div style="background: rgba(30, 41, 59, 0.5); border-radius: 0.5rem; padding: 1rem; overflow-x: auto;">';
        html += '<table style="width: 100%; font-size: 0.875rem;">';
        html += '<thead><tr style="color: #94a3b8; text-align: left; border-bottom: 1px solid #334155;">';
        html += '<th style="padding: 0.5rem;">Feature</th><th style="padding: 0.5rem;">Value</th>';
        html += '</tr></thead><tbody>';

        const featureList = [
            ['Connection Count', features.connectionCount],
            ['Duration', Utils.formatDuration(features.durationMs)],
            ['Mean Interval', Utils.formatDuration(features.meanInterval)],
            ['Median Interval', Utils.formatDuration(features.medianInterval)],
            ['Std Dev Interval', Utils.formatDuration(features.stdDevInterval)],
            ['Periodicity', (features.periodicity * 100).toFixed(2) + '%'],
            ['Jitter', (features.jitter * 100).toFixed(2) + '%'],
            ['Timing Entropy', features.timingEntropy.toFixed(2)],
            ['Mean Payload', Utils.formatBytes(features.meanPayload)],
            ['Payload Consistency', (features.payloadConsistency * 100).toFixed(2) + '%'],
            ['Unique Destinations', features.uniqueDestinations],
            ['Unique Sources', features.uniqueSources],
            ['Port Diversity', (features.portDiversity * 100).toFixed(2) + '%'],
            ['Most Common Port', features.mostCommonPort || 'N/A']
        ];

        featureList.forEach(([name, value]) => {
            html += `
                <tr style="border-bottom: 1px solid #334155;">
                    <td style="padding: 0.5rem; color: #cbd5e1;">${name}</td>
                    <td style="padding: 0.5rem; color: #22d3ee; font-weight: 600;">${value}</td>
                </tr>
            `;
        });

        html += '</tbody></table>';
        html += '</div>';
        html += '</div>';
        return html;
    },

    renderExportButtons() {
        return `
            <div class="card fade-in">
                <div class="card-header">
                    <i class="fas fa-download icon-cyan"></i>
                    <span>Export Report</span>
                </div>
                <div class="button-group">
                    <button class="btn-cyan" onclick="downloadReport('json')">
                        <i class="fas fa-file-code"></i> Download JSON Report
                    </button>
                    <button class="btn-cyan" onclick="downloadReport('html')">
                        <i class="fas fa-file-alt"></i> Download HTML Report
                    </button>
                    <button class="btn-cyan" onclick="downloadReport('pdf')">
                        <i class="fas fa-file-pdf"></i> Print to PDF
                    </button>
                </div>
            </div>
        `;
    },

    showHistoryModal(history, onSelect) {
        // Create modal overlay
        const modal = document.createElement('div');
        modal.style.cssText = `
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            padding: 2rem;
        `;

        const modalContent = document.createElement('div');
        modalContent.style.cssText = `
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 0.75rem;
            max-width: 1000px;
            width: 100%;
            max-height: 80vh;
            overflow-y: auto;
            padding: 2rem;
        `;

        let html = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <h2 style="font-size: 1.5rem; font-weight: 700;">Analysis History</h2>
                <button onclick="this.closest('[style*=fixed]').remove()" style="background: #1e293b; border: none; color: #f8fafc; padding: 0.5rem 1rem; border-radius: 0.5rem; cursor: pointer;">
                    <i class="fas fa-times"></i> Close
                </button>
            </div>
        `;

        if (history.length === 0) {
            html += '<p style="color: #94a3b8; text-align: center; padding: 2rem;">No analysis history yet</p>';
        } else {
            history.forEach(analysis => {
                const date = new Date(analysis.timestamp).toLocaleString();
                const badgeClass = this.getBadgeClass(analysis.classification);
                
                html += `
                    <div style="background: rgba(30, 41, 59, 0.5); border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; cursor: pointer;"
                         onclick="this.closest('[style*=fixed]').remove(); (${onSelect.toString()})(${JSON.stringify(analysis).replace(/"/g, '&quot;')})">
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <div>
                                <div style="font-weight: 600; color: #f8fafc; margin-bottom: 0.25rem;">
                                    ${analysis.fileName || 'Unknown File'}
                                </div>
                                <div style="font-size: 0.875rem; color: #94a3b8;">
                                    ${date}
                                </div>
                            </div>
                            <span class="badge ${badgeClass}" style="font-size: 0.875rem; padding: 0.25rem 1rem;">
                                ${analysis.classification}
                            </span>
                        </div>
                        <div style="margin-top: 0.75rem; font-size: 0.875rem; color: #cbd5e1;">
                            Score: ${analysis.score} | Connections: ${analysis.connectionCount || 0}
                        </div>
                    </div>
                `;
            });
        }

        modalContent.innerHTML = html;
        modal.appendChild(modalContent);
        document.body.appendChild(modal);

        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });
    },

    // Helper methods
    getBadgeClass(classification) {
        const mapping = {
            'CRITICAL': 'badge-critical',
            'SUSPICIOUS': 'badge-high',
            'MONITOR': 'badge-medium',
            'BENIGN': 'badge-info'
        };
        return mapping[classification] || 'badge-info';
    },

    getProgressClass(classification) {
        const mapping = {
            'CRITICAL': 'progress-critical',
            'SUSPICIOUS': 'progress-high',
            'MONITOR': 'progress-medium',
            'BENIGN': 'progress-low'
        };
        return mapping[classification] || 'progress-low';
    },

    getScoreColor(score) {
        if (score >= 80) return '#fca5a5';
        if (score >= 65) return '#fdba74';
        if (score >= 45) return '#fef08a';
        return '#86efac';
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = UI;
}
