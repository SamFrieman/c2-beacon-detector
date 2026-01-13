// Main Application Controller v2.1
let currentAnalysis = null;
let currentFileName = null;
let currentConnections = null;

// Initialize the application
async function initializeApp() {
    try {
        // Initialize threat intelligence
        const stats = await ThreatIntel.initialize();
        updateThreatIntelStatus(stats);

        // Initialize ML if available
        if (typeof MLDetector !== 'undefined' && MLDetector.initialize) {
            await MLDetector.initialize();
        }

        console.log('✓ All systems initialized');
    } catch (error) {
        console.error('Initialization error:', error);
        
        // Show error but allow degraded operation
        document.getElementById('threatIntelContent').innerHTML = `
            <div style="color: #f87171;">
                <p>⚠️ Initialization encountered errors, but the tool can still operate with reduced capabilities.</p>
                <p style="font-size: 0.875rem; margin-top: 0.5rem; color: #fca5a5;">Error: ${error.message}</p>
            </div>
        `;
    }
}

// Enhanced analysis with all v2.1 features
async function analyzeConnections(connections, fileName) {
    currentFileName = fileName;
    currentConnections = connections;
    UI.hideError();
    UI.showLoading('Processing network data...');

    try {
        // Validate connections
        const validation = Utils.validateConnections(connections);
        if (!validation.isValid) {
            throw new Error(validation.errors.join('. '));
        }

        // Update file badge
        UI.updateFileBadge(fileName, connections.length);

        // Step 1: Extract behavioral features
        UI.updateLoadingStatus('Extracting behavioral features...');
        await new Promise(resolve => setTimeout(resolve, 500));
        const features = Analyzer.extractFeatures(connections);

        // Step 2: Check threat intelligence (multi-source)
        UI.updateLoadingStatus('Checking threat intelligence databases...');
        let threatIntelMatches = [];
        
        try {
            threatIntelMatches = await ThreatIntel.checkConnections(connections);
            console.log(`Found ${threatIntelMatches.length} threat intel matches`);
        } catch (err) {
            console.warn('Threat intel lookup failed:', err);
        }

        // Step 3: ML prediction
        UI.updateLoadingStatus('Running machine learning models...');
        await new Promise(resolve => setTimeout(resolve, 300));
        let mlResults = null;
        
        try {
            mlResults = await MLDetector.predict(features);
            console.log('ML prediction:', mlResults?.ensemble?.prediction);
        } catch (err) {
            console.warn('ML prediction failed:', err);
        }

        // Step 4: Run detection engine
        UI.updateLoadingStatus('Running detection algorithms...');
        await new Promise(resolve => setTimeout(resolve, 500));
        const result = Detector.detect(features, threatIntelMatches);
        
        // Add ML results to analysis
        result.mlResults = mlResults;

        // Step 5: Compare with historical data
        UI.updateLoadingStatus('Comparing with historical analyses...');
        const comparison = HistoryManager.compareWithHistory(result);
        result.historicalComparison = comparison;

        // Save to history
        const analysisId = HistoryManager.saveAnalysis(result, fileName, connections);
        result.analysisId = analysisId;

        // Train ML on new data
        if (HistoryManager.history.length > 10) {
            MLDetector.trainOnHistory(HistoryManager.history);
        }

        currentAnalysis = result;

        // Display results
        UI.showResults(result);
        
    } catch (err) {
        UI.hideLoading();
        UI.showError(err.message);
        document.getElementById('infoSection').classList.remove('hidden');
    }
}

// Analyze sample data
function analyzeSample(type) {
    const connections = Utils.generateSampleData(type);
    const fileName = `Sample: ${type.charAt(0).toUpperCase() + type.slice(1).replace('-', ' ')}`;
    analyzeConnections(connections, fileName);
}

// Download enhanced reports
function downloadReport(format = 'json') {
    if (!currentAnalysis || !currentConnections) {
        console.warn('No analysis available to download');
        return;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);

    if (format === 'json') {
        const report = ReportGenerator.generateJSON(
            currentAnalysis,
            currentFileName,
            currentConnections
        );
        Utils.downloadJSON(report, `c2-analysis-${timestamp}.json`);
    } else if (format === 'html') {
        ReportGenerator.downloadHTML(
            currentAnalysis,
            currentFileName,
            currentConnections
        );
    } else if (format === 'pdf') {
        ReportGenerator.printToPDF(
            currentAnalysis,
            currentFileName,
            currentConnections
        );
    }
}

// Custom rule management
function addCustomRule() {
    const type = prompt('Rule type (ip/cidr):', 'ip');
    const value = prompt('Value (e.g., 192.168.1.100 or 10.0.0.0/8):', '');
    const malware = prompt('Malware family:', 'Custom C2');
    const confidence = parseInt(prompt('Confidence (0-100):', '75'));
    
    if (value) {
        const rule = ThreatIntel.addCustomRule({
            type: type,
            value: value,
            malware: malware,
            confidence: confidence,
            threat_type: 'custom',
            tags: ['custom']
        });
        
        alert(`Rule added: ${rule.id}`);
        updateCustomRulesUI();
    }
}

function updateCustomRulesUI() {
    const status = ThreatIntel.getStatus();
    UI.updateThreatIntelStatus(status);
}

// History management
function viewHistory() {
    const history = HistoryManager.getHistory(20);
    console.log('Recent analyses:', history);
    
    // Create modal or panel to display history
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
        background: white; padding: 2rem; border-radius: 0.5rem;
        box-shadow: 0 10px 40px rgba(0,0,0,0.3); max-width: 800px; max-height: 80vh;
        overflow-y: auto; z-index: 1000;
    `;
    
    modal.innerHTML = `
        <h2 style="margin-bottom: 1rem;">Analysis History</h2>
        <table style="width: 100%; border-collapse: collapse;">
            <tr style="background: #f3f4f6;">
                <th style="padding: 0.5rem; text-align: left;">Date</th>
                <th style="padding: 0.5rem; text-align: left;">File</th>
                <th style="padding: 0.5rem; text-align: left;">Score</th>
                <th style="padding: 0.5rem; text-align: left;">Classification</th>
            </tr>
            ${history.map(h => `
                <tr style="border-bottom: 1px solid #e5e7eb;">
                    <td style="padding: 0.5rem;">${new Date(h.timestamp).toLocaleString()}</td>
                    <td style="padding: 0.5rem;">${h.fileName}</td>
                    <td style="padding: 0.5rem;"><strong>${h.summary.score}%</strong></td>
                    <td style="padding: 0.5rem;">${h.summary.classification}</td>
                </tr>
            `).join('')}
        </table>
        <button onclick="this.parentElement.remove()" style="margin-top: 1rem; padding: 0.5rem 1rem; background: #3b82f6; color: white; border: none; border-radius: 0.25rem; cursor: pointer;">
            Close
        </button>
    `;
    
    document.body.appendChild(modal);
}

function exportHistory(format = 'json') {
    const data = HistoryManager.exportHistory(format);
    const blob = new Blob([data], { 
        type: format === 'json' ? 'application/json' : 'text/csv' 
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `c2detector-history-${Date.now()}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
}

// File upload handler
document.getElementById('fileInput').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    UI.hideError();

    try {
        const text = await file.text();
        const connections = Utils.parseJSON(text);
        analyzeConnections(connections, file.name);
    } catch (err) {
        UI.showError(`Failed to parse file: ${err.message}`);
    }
});

// Drag and drop support
const uploadZone = document.getElementById('uploadZone');

uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.style.borderColor = '#22d3ee';
    uploadZone.style.background = 'rgba(34, 211, 238, 0.05)';
});

uploadZone.addEventListener('dragleave', (e) => {
    e.preventDefault();
    uploadZone.style.borderColor = '#475569';
    uploadZone.style.background = '';
});

uploadZone.addEventListener('drop', async (e) => {
    e.preventDefault();
    uploadZone.style.borderColor = '#475569';
    uploadZone.style.background = '';
    
    const file = e.dataTransfer.files[0];
    if (!file) return;
    
    if (!file.name.endsWith('.json')) {
        UI.showError('Please upload a JSON file');
        return;
    }

    UI.hideError();

    try {
        const text = await file.text();
        const connections = Utils.parseJSON(text);
        analyzeConnections(connections, file.name);
    } catch (err) {
        UI.showError(`Failed to parse file: ${err.message}`);
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + H: View history
    if ((e.ctrlKey || e.metaKey) && e.key === 'h') {
        e.preventDefault();
        viewHistory();
    }
    
    // Ctrl/Cmd + E: Export current report
    if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
        e.preventDefault();
        if (currentAnalysis) {
            downloadReport('json');
        }
    }
});

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});
