// Main Application Controller
let currentAnalysis = null;
let currentFileName = null;
let currentConnections = null;

// Initialize the application
async function initializeApp() {
    console.log('Initializing C2 Beacon Detector...');
    
    // Initialize threat intelligence
    const threatIntelActive = await ThreatIntel.initialize();
    const status = ThreatIntel.getStatus();
    UI.updateThreatIntelStatus(status);
    
    if (threatIntelActive) {
        console.log('Threat intelligence feeds loaded successfully');
    } else {
        console.warn('Running in offline mode - behavioral analysis only');
    }
}

// Analyze connections with full threat intelligence
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

        // Extract behavioral features
        UI.updateLoadingStatus('Extracting behavioral features...');
        await new Promise(resolve => setTimeout(resolve, 500));
        const features = Analyzer.extractFeatures(connections);

        // Check threat intelligence
        UI.updateLoadingStatus('Checking threat intelligence databases...');
        let threatIntelMatches = [];
        
        try {
            threatIntelMatches = await ThreatIntel.checkConnections(connections);
            console.log(`Found ${threatIntelMatches.length} threat intel matches`);
        } catch (err) {
            console.warn('Threat intel lookup failed:', err);
        }

        // Run detection
        UI.updateLoadingStatus('Running detection algorithms...');
        await new Promise(resolve => setTimeout(resolve, 500));
        const result = Detector.detect(features, threatIntelMatches);
        
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

// Download analysis report
function downloadReport() {
    if (!currentAnalysis || !currentConnections) {
        console.warn('No analysis available to download');
        return;
    }

    const report = Detector.generateReport(
        currentAnalysis,
        currentFileName,
        currentConnections
    );

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    Utils.downloadJSON(report, `c2-analysis-${timestamp}.json`);
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

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});
