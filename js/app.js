// app.js - Main Application Controller with Robust Error Handling
// Version 2.1.1

const C2DetectorApp = {
    state: {
        initialized: false,
        currentAnalysis: null,
        fileName: null,
        modules: {
            utils: false,
            threatIntel: false,
            mlDetector: false,
            historyManager: false,
            reportGenerator: false,
            analyzer: false,
            detector: false,
            ui: false
        }
    },

    async initialize() {
        console.log('Initializing C2 Beacon Detector v2.1...');
        
        // Check for required modules
        this.checkModules();
        
        // Initialize UI elements
        this.initializeUI();
        
        // Initialize modules in correct order
        await this.initializeModules();
        
        // Setup event listeners
        this.setupEventListeners();
        
        // Keyboard shortcuts
        this.setupKeyboardShortcuts();
        
        this.state.initialized = true;
        console.log('✓ Application initialized successfully');
        console.log('  - Modules loaded:', Object.keys(this.state.modules).filter(k => this.state.modules[k]).length);
    },

    checkModules() {
        // Check which modules are available
        this.state.modules.utils = typeof Utils !== 'undefined';
        this.state.modules.threatIntel = typeof ThreatIntel !== 'undefined';
        this.state.modules.mlDetector = typeof MLDetector !== 'undefined';
        this.state.modules.historyManager = typeof HistoryManager !== 'undefined';
        this.state.modules.reportGenerator = typeof ReportGenerator !== 'undefined';
        this.state.modules.analyzer = typeof Analyzer !== 'undefined';
        this.state.modules.detector = typeof Detector !== 'undefined';
        this.state.modules.ui = typeof UI !== 'undefined';

        const missing = Object.keys(this.state.modules).filter(k => !this.state.modules[k]);
        if (missing.length > 0) {
            console.warn('⚠ Missing modules:', missing);
            console.warn('Some features may be unavailable');
        }
    },

    initializeUI() {
        // Hide loading on startup
        const loadingSection = document.getElementById('loadingSection');
        const errorSection = document.getElementById('errorSection');
        const resultsSection = document.getElementById('resultsSection');
        
        if (loadingSection) loadingSection.classList.add('hidden');
        if (errorSection) errorSection.classList.add('hidden');
        if (resultsSection) resultsSection.classList.add('hidden');
    },

    async initializeModules() {
        try {
            // Initialize Threat Intelligence
            if (this.state.modules.threatIntel) {
                const stats = await ThreatIntel.initialize();
                this.updateThreatIntelStatus(stats);
            }

            // Initialize ML Detector
            if (this.state.modules.mlDetector) {
                await MLDetector.initialize();
                console.log('✓ ML models initialized');
            }

            // Initialize History Manager
            if (this.state.modules.historyManager) {
                const historyCount = HistoryManager.initialize();
                console.log(`✓ Loaded ${historyCount} historical analyses`);
            }

            console.log('✓ All systems initialized');
        } catch (error) {
            console.error('Initialization error:', error);
            this.showError('Initialization Error', error.message, true);
        }
    },

    setupEventListeners() {
        // File input
        const fileInput = document.getElementById('fileInput');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        }

        // Upload zone drag and drop
        const uploadZone = document.getElementById('uploadZone');
        if (uploadZone) {
            uploadZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadZone.style.borderColor = '#22d3ee';
                uploadZone.style.background = 'rgba(34, 211, 238, 0.05)';
            });

            uploadZone.addEventListener('dragleave', (e) => {
                e.preventDefault();
                uploadZone.style.borderColor = '';
                uploadZone.style.background = '';
            });

            uploadZone.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadZone.style.borderColor = '';
                uploadZone.style.background = '';
                
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    this.handleFile(files[0]);
                }
            });
        }
    },

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl+H or Cmd+H - View History
            if ((e.ctrlKey || e.metaKey) && e.key === 'h') {
                e.preventDefault();
                this.viewHistory();
            }

            // Ctrl+E or Cmd+E - Export Report
            if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
                e.preventDefault();
                if (this.state.currentAnalysis) {
                    this.downloadReport('json');
                }
            }
        });
    },

    handleFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            this.handleFile(file);
        }
    },

    async handleFile(file) {
        if (!file.name.endsWith('.json')) {
            this.showError('Invalid File Type', 'Please upload a JSON file');
            return;
        }

        this.state.fileName = file.name;
        
        // Show file badge
        const fileBadge = document.getElementById('fileBadge');
        if (fileBadge) {
            fileBadge.innerHTML = `
                <i class="fas fa-file-code" style="color: #22d3ee;"></i>
                <span>${file.name}</span>
                <span style="color: #64748b;">(${this.formatBytes(file.size)})</span>
            `;
            fileBadge.classList.remove('hidden');
            fileBadge.className = 'file-badge';
        }

        // Read and parse file
        const reader = new FileReader();
        reader.onload = async (e) => {
            try {
                const jsonData = JSON.parse(e.target.result);
                await this.analyzeData(jsonData);
            } catch (error) {
                this.showError('Parse Error', 'Invalid JSON format: ' + error.message);
            }
        };
        reader.readAsText(file);
    },

    async analyzeData(jsonData) {
        try {
            // Hide error and results
            this.hideError();
            this.hideResults();
            
            // Show loading
            this.showLoading();

            // Validate data format
            if (!this.state.modules.utils) {
                throw new Error('Utils module not loaded');
            }

            const validationResult = Utils.validateJSON(jsonData);
            if (!validationResult.valid) {
                throw new Error(validationResult.error);
            }

            const connections = validationResult.data;
            console.log(`Analyzing ${connections.length} connections...`);

            // Update loading status
            this.updateLoadingStatus('Extracting behavioral features...');

            // Extract features
            if (!this.state.modules.analyzer) {
                throw new Error('Analyzer module not loaded');
            }

            const features = Analyzer.extractFeatures(connections);
            console.log('Features extracted:', Object.keys(features).length);

            // Update loading status
            this.updateLoadingStatus('Checking threat intelligence databases...');

            // Run detection
            if (!this.state.modules.detector) {
                throw new Error('Detector module not loaded');
            }

            const analysis = await Detector.analyze(features, connections);
            
            // Store current analysis
            this.state.currentAnalysis = {
                ...analysis,
                fileName: this.state.fileName,
                timestamp: new Date().toISOString(),
                connectionCount: connections.length
            };

            // Save to history
            if (this.state.modules.historyManager) {
                HistoryManager.addAnalysis(this.state.currentAnalysis);
            }

            // Update loading status
            this.updateLoadingStatus('Generating report...');

            // Display results
            this.hideLoading();
            this.showResults(this.state.currentAnalysis, connections);

            console.log(`Analysis complete: ${analysis.classification} (Score: ${analysis.score})`);

        } catch (error) {
            console.error('Analysis error:', error);
            this.hideLoading();
            this.showError('Analysis Error', error.message);
        }
    },

    // Sample data analysis
    async analyzeSample(type) {
        if (!this.state.modules.utils) {
            this.showError('Error', 'Utils module not loaded');
            return;
        }

        let sampleData;
        let fileName;

        switch (type) {
            case 'cobalt-strike':
                sampleData = Utils.generateCobaltStrikeSample();
                fileName = 'cobalt-strike-sample.json';
                break;
            case 'metasploit':
                sampleData = Utils.generateMetasploitSample();
                fileName = 'metasploit-sample.json';
                break;
            case 'benign':
                sampleData = Utils.generateBenignSample();
                fileName = 'benign-traffic-sample.json';
                break;
            default:
                this.showError('Error', 'Unknown sample type');
                return;
        }

        this.state.fileName = fileName;
        await this.analyzeData(sampleData);
    },

    // UI Update Methods
    showLoading() {
        const loadingSection = document.getElementById('loadingSection');
        if (loadingSection) {
            loadingSection.classList.remove('hidden');
        }
    },

    hideLoading() {
        const loadingSection = document.getElementById('loadingSection');
        if (loadingSection) {
            loadingSection.classList.add('hidden');
        }
    },

    updateLoadingStatus(message) {
        const statusElement = document.getElementById('loadingStatus');
        if (statusElement) {
            statusElement.textContent = message;
        }
    },

    showError(title, message, isWarning = false) {
        const errorSection = document.getElementById('errorSection');
        if (!errorSection) return;

        const iconClass = isWarning ? 'fa-exclamation-triangle' : 'fa-exclamation-circle';
        const borderColor = isWarning ? '#eab308' : '#b91c1c';

        errorSection.innerHTML = `
            <div class="error-card fade-in" style="border-color: ${borderColor};">
                <i class="fas ${iconClass} error-icon"></i>
                <div>
                    <div class="error-title">${title}</div>
                    <div class="error-text">${message}</div>
                </div>
            </div>
        `;
        errorSection.classList.remove('hidden');
    },

    hideError() {
        const errorSection = document.getElementById('errorSection');
        if (errorSection) {
            errorSection.classList.add('hidden');
        }
    },

    showResults(analysis, connections) {
        if (!this.state.modules.ui) {
            this.showError('Error', 'UI module not loaded');
            return;
        }

        const resultsSection = document.getElementById('resultsSection');
        if (resultsSection) {
            resultsSection.innerHTML = UI.renderResults(analysis, connections, this.state.fileName);
            resultsSection.classList.remove('hidden');
            
            // Scroll to results
            resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        // Hide info section
        const infoSection = document.getElementById('infoSection');
        if (infoSection) {
            infoSection.style.display = 'none';
        }
    },

    hideResults() {
        const resultsSection = document.getElementById('resultsSection');
        if (resultsSection) {
            resultsSection.classList.add('hidden');
        }

        // Show info section
        const infoSection = document.getElementById('infoSection');
        if (infoSection) {
            infoSection.style.display = 'block';
        }
    },

    updateThreatIntelStatus(stats) {
        const statusElement = document.getElementById('threatIntelContent');
        if (!statusElement) return;

        const sources = stats.sources || {};
        const threatfoxStatus = sources.threatfox || {};
        const customRulesStatus = sources.customRules || {};

        let html = '<div class="intel-status">';

        // ThreatFox
        html += '<div class="intel-feed">';
        html += '<div class="intel-feed-header">';
        html += `<span class="status-dot ${threatfoxStatus.status === 'active' ? 'status-active' : 'status-inactive'}"></span>`;
        html += '<span>ThreatFox API</span>';
        html += '</div>';
        html += '<div class="intel-feed-info">';
        if (threatfoxStatus.status === 'active') {
            html += `✓ Online - ${threatfoxStatus.iocs || 0} IOCs loaded`;
        } else {
            html += '⚠ Offline - Using local detection';
        }
        html += '</div></div>';

        // Custom Rules
        html += '<div class="intel-feed">';
        html += '<div class="intel-feed-header">';
        html += `<span class="status-dot status-active"></span>`;
        html += '<span>Custom Rules</span>';
        html += '</div>';
        html += '<div class="intel-feed-info">';
        html += `✓ Active - ${customRulesStatus.count || 0} rule(s)`;
        html += '</div></div>';

        // ML Status
        html += '<div class="intel-feed">';
        html += '<div class="intel-feed-header">';
        html += `<span class="status-dot status-active"></span>`;
        html += '<span>Machine Learning</span>';
        html += '</div>';
        html += '<div class="intel-feed-info">';
        html += '✓ Enabled - Models ready';
        html += '</div></div>';

        html += '</div>';

        // Warning if ThreatFox offline
        if (threatfoxStatus.status !== 'active') {
            html += `
                <div style="margin-top: 1rem; padding: 1rem; background: rgba(234, 179, 8, 0.1); 
                     border-left: 3px solid #eab308; border-radius: 0.5rem;">
                    <p style="font-size: 0.875rem; color: #fef08a; margin: 0;">
                        <strong>ℹ️ Note:</strong> ThreatFox API unavailable. Detection continues with behavioral analysis and ML models.
                    </p>
                </div>
            `;
        }

        statusElement.innerHTML = html;
    },

    // History viewing
    viewHistory() {
        if (!this.state.modules.historyManager || !this.state.modules.ui) {
            this.showError('Error', 'History module not loaded');
            return;
        }

        const history = HistoryManager.getHistory();
        UI.showHistoryModal(history, (analysis) => {
            // Callback to load an analysis from history
            this.loadFromHistory(analysis);
        });
    },

    loadFromHistory(analysis) {
        this.state.currentAnalysis = analysis;
        this.state.fileName = analysis.fileName || 'historical-analysis.json';
        
        // We don't have original connections, so create minimal display
        this.hideError();
        this.hideLoading();
        
        // Show results without full connection data
        this.showResults(analysis, []);
    },

    // Report download
    downloadReport(format) {
        if (!this.state.currentAnalysis) {
            this.showError('Error', 'No analysis available to export');
            return;
        }

        if (!this.state.modules.reportGenerator) {
            this.showError('Error', 'Report generator not loaded');
            return;
        }

        try {
            switch (format) {
                case 'json':
                    ReportGenerator.downloadJSON(
                        this.state.currentAnalysis,
                        this.state.fileName || 'analysis.json'
                    );
                    break;
                case 'html':
                    ReportGenerator.downloadHTML(
                        this.state.currentAnalysis,
                        this.state.fileName || 'report.html'
                    );
                    break;
                case 'pdf':
                    ReportGenerator.printToPDF(this.state.currentAnalysis);
                    break;
                default:
                    throw new Error('Unknown format: ' + format);
            }
            console.log(`✓ Report downloaded: ${format}`);
        } catch (error) {
            console.error('Download error:', error);
            this.showError('Export Error', error.message);
        }
    },

    // Utility methods
    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    }
};

// Global functions for HTML onclick handlers
function analyzeSample(type) {
    C2DetectorApp.analyzeSample(type);
}

function viewHistory() {
    C2DetectorApp.viewHistory();
}

function downloadReport(format) {
    C2DetectorApp.downloadReport(format);
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => C2DetectorApp.initialize());
} else {
    C2DetectorApp.initialize();
}
