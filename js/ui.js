// UI Controller Module v2.1 - Enhanced
const UI = {
    showError(message) {
        const errorSection = document.getElementById('errorSection');
        errorSection.innerHTML = `
            <div class="error-card fade-in">
                <i class="fas fa-exclamation-circle error-icon"></i>
                <div>
                    <h3 class="error-title">Analysis Error</h3>
                    <p class="error-text">${message}</p>
                </div>
            </div>
        `;
        errorSection.classList.remove('hidden');
    },

    hideError() {
        document.getElementById('errorSection').classList.add('hidden');
    },

    showLoading(status = 'Analyzing behavioral patterns...') {
        document.getElementById('loadingSection').classList.remove('hidden');
        document.getElementById('resultsSection').classList.add('hidden');
        document.getElementById('infoSection').classList.add('hidden');
        
        const loadingStatus = document.getElementById('loadingStatus');
        if (loadingStatus) {
            loadingStatus.textContent = status;
        }
    },

    hideLoading() {
        document.getElementById('loadingSection').classList.add('hidden');
    },

    updateLoadingStatus(status) {
        const loadingStatus = document.getElementById('loadingStatus');
        if (loadingStatus) {
            loadingStatus.textContent = status;
        }
    },

    updateFileBadge(fileName, connectionCount) {
        const fileBadge = document.getElementById('fileBadge');
        fileBadge.innerHTML = `
            <i class="fas fa-file-alt icon-cyan"></i>
            <span style="font-size: 0.875rem;">${fileName}</span>
            <span style="font-size: 0.75rem; color: #64748b;">(${connectionCount} connections)</span>
        `;
        fileBadge.classList.remove('hidden');
    },

    updateThreatIntelStatus(status) {
        const statusElement = document.getElementById('threatIntelContent');
    
        if (!statusElement) return;
    
        const sources = stats.sources || {};
        const threatfoxStatus = sources.threatfox || {};
        const customRulesStatus = sources.customRules || {};

        // Build status HTML
        let html = '<div class="intel-status">';

        // ThreatFox Status
        html += '<div class="intel-feed">';
        html += '<div class="intel-feed-header">';
        html += `<span class="status-dot ${threatfoxStatus.status === 'active' ? 'status-active' : 'status-inactive'}"></span>`;
        html += '<span>ThreatFox API</span>';
        html += '</div>';
        html += '<div class="intel-feed-info">';

        if (threatfoxStatus.status === 'active') {
            html += `✓ Online - ${threatfoxStatus.iocs || 0} IOCs loaded`;
        } else {
            html += '⚠ Offline - Working in degraded mode';
            if (stats.error) {
                html += `<br><small style="color: #f87171;">Error: ${stats.error}</small>`;
            }
        }

        html += '</div>';
        html += '</div>';

        // Custom Rules Status
        html += '<div class="intel-feed">';
        html += '<div class="intel-feed-header">';
        html += `<span class="status-dot ${customRulesStatus.status === 'active' ? 'status-active' : 'status-inactive'}"></span>`;
        html += '<span>Custom Rules</span>';
        html += '</div>';
        html += '<div class="intel-feed-info">';
        html += `✓ Active - ${customRulesStatus.count || 0} rule(s) loaded`;
        html += '</div>';
        html += '</div>';

        if (typeof MLDetector !== 'undefined') {
            const mlStats = MLDetector.getStats ? MLDetector.getStats() : { enabled: true };
            html += '<div class="intel-feed">';
            html += '<div class="intel-feed-header">';
            html += `<span class="status-dot status-active"></span>`;
            html += '<span>Machine Learning</span>';
            html += '</div>';
            html += '<div class="intel-feed-info">';
            html += `✓ Enabled - Beacon classifier active`;
            html += '</div>';
            html += '</div>';
        }

        html += '</div>';

        // Add informational message if ThreatFox is offline
        if (threatfoxStatus.status !== 'active') {
            html += `
                <div style="margin-top: 1rem; padding: 1rem; background: rgba(234, 179, 8, 0.1); border-left: 3px solid #eab308; border-radius: 0.5rem;">
                    <p style="font-size: 0.875rem; color: #fef08a; margin: 0;">
                        <strong>ℹ️ Note:</strong> ThreatFox API is currently unavailable. The tool will continue to work using:
                    </p>
                    <ul style="font-size: 0.875rem; color: #fef08a; margin: 0.5rem 0 0 1.5rem;">
                        <li>Custom detection rules</li>
                        <li>Behavioral analysis</li>
                        <li>Machine learning models</li>
                    </ul>
                </div>
            `;
        }
        
        statusElement.innerHTML = html;
    },

    renderThreatIntelMatches(matches) {
        if (!matches || matches.length === 0) return '';

        return `
            <div class="card fade-in">
                <div class="card-header">
                    <i class="fas fa-skull-crossbones" style="color: #ef4444;"></i>
                    <span>Threat Intelligence Matches (${matches.length})</span>
                </div>
                ${matches.map(match => `
                    <div class="threat-match">
                        <div class="threat-match-header">
                            <div class="threat-match-title">
                                <i class="fas fa-exclamation-triangle"></i>
                                <span>${match.ip}</span>
                            </div>
                            ${match.combinedThreatScore ? 
                                `<span class="threat-tag">Combined Score: ${match.combinedThreatScore}%</span>` : 
                                `<span class="threat-tag">${match.sources?.[0]?.threat_type || match.threat_type}</span>`
                            }
                        </div>
                        ${match.sources && match.sources.length > 1 ? `
                            <div style="margin-bottom: 1rem; padding: 0.5rem; background: rgba(220, 38, 38, 0.1); border-radius: 0.25rem;">
                                <strong>⚠️ Multiple Sources Detected (${match.sources.length})</strong>
                            </div>
                        ` : ''}
                        <div class="threat-details">
                            ${match.sources ? match.sources.map(source => `
                                <div style="margin-bottom: 1rem; padding: 0.75rem; background: rgba(30, 41, 59, 0.3); border-radius: 0.25rem;">
                                    <div style="font-weight: 600; color: #22d3ee; margin-bottom: 0.5rem;">
                                        Source: ${source.source}
                                    </div>
                                    <div class="threat-detail">
                                        <span class="threat-detail-label">Malware:</span>
                                        <span class="threat-detail-value">${source.malware}</span>
                                    </div>
                                    <div class="threat-detail">
                                        <span class="threat-detail-label">Confidence:</span>
                                        <span class="threat-detail-value">${source.confidence_level}%</span>
                                    </div>
                                    ${source.first_seen ? `
                                        <div class="threat-detail">
                                            <span class="threat-detail-label">First Seen:</span>
                                            <span class="threat-detail-value">${source.first_seen}</span>
                                        </div>
                                    ` : ''}
                                </div>
                            `).join('') : `
                                <div class="threat-detail">
                                    <span class="threat-detail-label">Malware:</span>
                                    <span class="threat-detail-value">${match.malware}</span>
                                </div>
                                <div class="threat-detail">
                                    <span class="threat-detail-label">Confidence:</span>
                                    <span class="threat-detail-value">${match.confidence_level}%</span>
                                </div>
                            `}
                            <div class="threat-detail">
                                <span class="threat-detail-label">Connections:</span>
                                <span class="threat-detail-value">${match.connection_count}</span>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },

    renderMLResults(mlResults) {
        if (!mlResults) return '';

        const ensemble = mlResults.ensemble;
        const anomaly = mlResults.models?.anomaly_detector;

        return `
            <div class="card fade-in">
                <div class="card-header">
                    <i class="fas fa-brain icon-cyan"></i>
                    <span>Machine Learning Analysis</span>
                </div>
                
                <div class="grid grid-2">
                    <div class="framework-card">
                        <div class="framework-header">
                            <span class="framework-name">Ensemble Prediction</span>
                            <span class="confidence-badge confidence-${ensemble?.confidence === 'high' ? 'high' : 'medium'}">
                                ${ensemble?.confidence || 'N/A'}
                            </span>
                        </div>
                        <p style="font-size: 1.5rem; font-weight: 700; margin: 0.5rem 0; color: ${
                            ensemble?.prediction === 'malicious' ? '#ef4444' : 
                            ensemble?.prediction === 'suspicious' ? '#f59e0b' : '#22c55e'
                        };">
                            ${ensemble?.prediction?.toUpperCase() || 'UNKNOWN'}
                        </p>
                        <p class="framework-reason">
                            ML Score: ${ensemble ? (ensemble.score * 100).toFixed(1) : 'N/A'}%
                        </p>
                    </div>

                    <div class="framework-card">
                        <div class="framework-header">
                            <span class="framework-name">Anomaly Detection</span>
                            <span class="confidence-badge ${anomaly?.is_anomaly ? 'confidence-high' : 'confidence-low'}">
                                ${anomaly?.is_anomaly ? 'ANOMALY' : 'NORMAL'}
                            </span>
                        </div>
                        <p style="font-size: 1.5rem; font-weight: 700; margin: 0.5rem 0;">
                            ${anomaly ? (anomaly.anomaly_score * 100).toFixed(1) : 'N/A'}%
                        </p>
                        <p class="framework-reason">
                            ${anomaly?.anomaly_factors?.length || 0} anomaly factor(s) detected
                        </p>
                    </div>
                </div>

                ${anomaly?.anomaly_factors && anomaly.anomaly_factors.length > 0 ? `
                    <details style="margin-top: 1rem;">
                        <summary>Anomaly Factors (${anomaly.anomaly_factors.length})</summary>
                        <div style="margin-top: 0.75rem;">
                            ${anomaly.anomaly_factors.map(f => `
                                <p style="font-size: 0.875rem; color: #cbd5e1; margin-bottom: 0.5rem;">
                                    • ${f.factor.replace(/_/g, ' ')}: ${(f.score * 100).toFixed(1)}%
                                </p>
                            `).join('')}
                        </div>
                    </details>
                ` : ''}
            </div>
        `;
    },

    renderHistoricalComparison(comparison) {
        if (!comparison || !comparison.hasEnoughData) return '';

        return `
            <div class="card fade-in">
                <div class="card-header">
                    <i class="fas fa-chart-line icon-cyan"></i>
                    <span>Historical Comparison</span>
                </div>
                
                <p style="color: #94a3b8; margin-bottom: 1rem;">
                    Compared with ${comparison.totalHistoricalAnalyses} previous analyses
                </p>

                <div style="margin-bottom: 1rem;">
                    ${comparison.interpretation.map(interp => `
                        <div class="factor-item">${interp}</div>
                    `).join('')}
                </div>

                ${comparison.similarAnalyses && comparison.similarAnalyses.length > 0 ? `
                    <details>
                        <summary>Similar Analyses (${comparison.similarAnalyses.length})</summary>
                        <table style="width: 100%; margin-top: 0.75rem; font-size: 0.875rem;">
                            <tr style="background: rgba(30, 41, 59, 0.3);">
                                <th style="padding: 0.5rem; text-align: left;">File</th>
                                <th style="padding: 0.5rem; text-align: left;">Score</th>
                                <th style="padding: 0.5rem; text-align: left;">Similarity</th>
                            </tr>
                            ${comparison.similarAnalyses.map(sim => `
                                <tr style="border-bottom: 1px solid rgba(51, 65, 85, 0.3);">
                                    <td style="padding: 0.5rem;">${sim.fileName}</td>
                                    <td style="padding: 0.5rem;"><strong>${sim.score}%</strong></td>
                                    <td style="padding: 0.5rem;">${sim.similarity}%</td>
                                </tr>
                            `).join('')}
                        </table>
                    </details>
                ` : ''}
            </div>
        `;
    },

    renderMITRETechniques(techniques) {
        if (!techniques || techniques.length === 0) return '';

        return `
            <div class="card fade-in">
                <div class="card-header">
                    <i class="fas fa-shield-virus icon-cyan"></i>
                    <span>MITRE ATT&CK Mapping</span>
                </div>
                <div class="grid grid-2">
                    ${techniques.map(tech => `
                        <div class="framework-card">
                            <div class="framework-header">
                                <span class="framework-name">${tech.id}</span>
                                <span class="confidence-badge confidence-high">${tech.tactic}</span>
                            </div>
                            <p style="font-weight: 600; margin-bottom: 0.5rem; color: #cbd5e1;">${tech.name}</p>
                            <p class="framework-reason">${tech.description}</p>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    showResults(result) {
        this.hideLoading();
        document.getElementById('infoSection').classList.add('hidden');
        
        const resultsSection = document.getElementById('resultsSection');
        
        const badgeClass = {
            'critical': 'badge-critical',
            'high': 'badge-high',
            'medium': 'badge-medium',
            'info': 'badge-info'
        }[result.severity];

        const progressClass = {
            'critical': 'progress-critical',
            'high': 'progress-high',
            'medium': 'progress-medium',
            'info': 'progress-low'
        }[result.severity];

        const threatIntelHTML = this.renderThreatIntelMatches(result.threatIntelMatches);
        const mlHTML = this.renderMLResults(result.mlResults);
        const historyHTML = this.renderHistoricalComparison(result.historicalComparison);
        const mitreHTML = this.renderMITRETechniques(result.mitreTechniques);

        let frameworksHTML = '';
        if (result.identifiedFrameworks && result.identifiedFrameworks.length > 0) {
            const confidenceClass = (conf) => {
                if (conf === 'High') return 'confidence-high';
                if (conf === 'Medium') return 'confidence-medium';
                return 'confidence-low';
            };

            frameworksHTML = `
                <div class="card fade-in">
                    <div class="card-header">
                        <i class="fas fa-fingerprint icon-cyan"></i>
                        <span>Potential C2 Frameworks</span>
                    </div>
                    <div class="grid grid-2">
                        ${result.identifiedFrameworks.map(fw => `
                            <div class="framework-card">
                                <div class="framework-header">
                                    <span class="framework-name">${fw.name}</span>
                                    <span class="confidence-badge ${confidenceClass(fw.confidence)}">${fw.confidence}</span>
                                </div>
                                <p class="framework-reason">${fw.reason}</p>
                                ${fw.source ? `<p style="font-size: 0.75rem; color: #64748b; margin-top: 0.25rem;">Source: ${fw.source}</p>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        let technicalHTML = '';
        if (result.technicalDetails && result.technicalDetails.length > 0) {
            technicalHTML = `
                <details style="margin-top: 1.5rem;">
                    <summary>Technical Details (${result.technicalDetails.length})</summary>
                    <div style="margin-top: 0.75rem;">
                        ${result.technicalDetails.map(detail => `
                            <p style="font-size: 0.75rem; color: #64748b; font-family: monospace; margin-bottom: 0.25rem;">• ${detail}</p>
                        `).join('')}
                    </div>
                </details>
            `;
        }

        resultsSection.innerHTML = `
            <div class="card fade-in">
                <div class="result-header">
                    <h2>Analysis Results</h2>
                    <div class="badge-group">
                        <span class="badge ${badgeClass}">${result.classification}</span>
                        <button class="btn-cyan" onclick="downloadReport('json')">
                            <i class="fas fa-download"></i>
                            <span>JSON</span>
                        </button>
                        <button class="btn-cyan" onclick="downloadReport('html')">
                            <i class="fas fa-file-code"></i>
                            <span>HTML</span>
                        </button>
                        <button class="btn-purple" onclick="downloadReport('pdf')">
                            <i class="fas fa-file-pdf"></i>
                            <span>PDF</span>
                        </button>
                    </div>
                </div>

                <div class="progress-section">
                    <div class="progress-header">
                        <span class="progress-label">Threat Probability</span>
                        <span class="progress-value">${result.score}%</span>
                    </div>
                    <div class="progress-bg">
                        <div class="progress-bar ${progressClass}" style="width: ${result.score}%"></div>
                    </div>
                </div>

                <div class="recommendation">
                    <h3>
                        <i class="fas fa-clipboard-list icon-cyan"></i>
                        Recommendation
                    </h3>
                    <p>${result.recommendation}</p>
                </div>

                <div>
                    <h3 style="display: flex; align-items: center; gap: 0.5rem; font-size: 1.125rem; font-weight: 600; margin-bottom: 1rem;">
                        <i class="fas fa-search icon-cyan"></i>
                        Detection Factors (${result.reasons.length})
                    </h3>
                    <div class="factors-list">
                        ${result.reasons.map(reason => `
                            <div class="factor-item">${reason}</div>
                        `).join('')}
                    </div>
                </div>

                ${technicalHTML}
            </div>

            ${threatIntelHTML}
            ${mlHTML}
            ${historyHTML}
            ${mitreHTML}
            ${frameworksHTML}

            <div class="card fade-in">
                <div class="card-header">
                    <i class="fas fa-chart-line icon-cyan"></i>
                    <span>Extracted Features</span>
                </div>
                <div class="grid grid-4">
                    ${Object.entries(result.features).map(([key, value]) => `
                        <div class="feature-card">
                            <div class="feature-label">${key.replace(/_/g, ' ')}</div>
                            <div class="feature-value">
                                ${typeof value === 'number' ? 
                                    (value < 1 && value > 0 ? value.toFixed(4) : value.toFixed(2)) : 
                                    value}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        resultsSection.classList.remove('hidden');
    }
};
