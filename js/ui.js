// UI Controller Module
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
        const content = document.getElementById('threatIntelContent');
        
        if (status.active) {
            content.innerHTML = `
                <div class="intel-status">
                    <div class="intel-feed">
                        <div class="intel-feed-header">
                            <span class="status-dot status-active"></span>
                            <span>ThreatFox</span>
                        </div>
                        <div class="intel-feed-info">
                            ${status.iocCount} IOCs loaded<br>
                            Last update: ${status.lastUpdate ? new Date(status.lastUpdate).toLocaleTimeString() : 'Never'}
                        </div>
                    </div>
                    <div class="intel-feed">
                        <div class="intel-feed-header">
                            <span class="status-dot status-active"></span>
                            <span>Source</span>
                        </div>
                        <div class="intel-feed-info">
                            ${status.source}
                        </div>
                    </div>
                </div>
            `;
        } else {
            content.innerHTML = `
                <div class="intel-status">
                    <div class="intel-feed">
                        <div class="intel-feed-header">
                            <span class="status-dot status-inactive"></span>
                            <span>Offline Mode</span>
                        </div>
                        <div class="intel-feed-info">
                            Threat intelligence unavailable<br>
                            Using behavioral analysis only
                        </div>
                    </div>
                </div>
            `;
        }
    },

    renderThreatIntelMatches(matches) {
        if (!matches || matches.length === 0) return '';

        return `
            <div class="card fade-in">
                <div class="card-header">
                    <i class="fas fa-skull-crossbones" style="color: #ef4444;"></i>
                    <span>Threat Intelligence Matches</span>
                </div>
                ${matches.map(match => `
                    <div class="threat-match">
                        <div class="threat-match-header">
                            <div class="threat-match-title">
                                <i class="fas fa-exclamation-triangle"></i>
                                <span>${match.ip}</span>
                            </div>
                            <span class="threat-tag">${match.threat_type}</span>
                        </div>
                        <div class="threat-details">
                            <div class="threat-detail">
                                <span class="threat-detail-label">Malware:</span>
                                <span class="threat-detail-value">${match.malware}</span>
                            </div>
                            ${match.malware_alias ? `
                                <div class="threat-detail">
                                    <span class="threat-detail-label">Alias:</span>
                                    <span class="threat-detail-value">${match.malware_alias}</span>
                                </div>
                            ` : ''}
                            <div class="threat-detail">
                                <span class="threat-detail-label">Confidence:</span>
                                <span class="threat-detail-value">${match.confidence_level}%</span>
                            </div>
                            <div class="threat-detail">
                                <span class="threat-detail-label">First Seen:</span>
                                <span class="threat-detail-value">${match.first_seen}</span>
                            </div>
                            <div class="threat-detail">
                                <span class="threat-detail-label">Connections:</span>
                                <span class="threat-detail-value">${match.connection_count}</span>
                            </div>
                            ${match.tags && match.tags.length > 0 ? `
                                <div class="threat-detail">
                                    <span class="threat-detail-label">Tags:</span>
                                    <span class="threat-detail-value">${match.tags.join(', ')}</span>
                                </div>
                            ` : ''}
                            ${match.reference ? `
                                <div class="threat-detail">
                                    <span class="threat-detail-label">Reference:</span>
                                    <span class="threat-detail-value">
                                        <a href="${match.reference}" target="_blank" style="color: #22d3ee;">
                                            ${match.reference}
                                        </a>
                                    </span>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `).join('')}
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
                        <button class="btn-cyan" onclick="downloadReport()">
                            <i class="fas fa-download"></i>
                            <span>Export Report</span>
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
