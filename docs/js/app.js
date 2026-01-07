/**
 * Main React Application Component
 * Orchestrates the UI and analysis workflow
 */

const { useState } = React;

const C2BeaconDetector = () => {
    const [analysisResult, setAnalysisResult] = useState(null);
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [uploadedFileName, setUploadedFileName] = useState(null);
    const [error, setError] = useState(null);
    const [connectionCount, setConnectionCount] = useState(0);

    /**
     * Handle file upload and trigger analysis
     */
    const handleFileUpload = async (event) => {
        const file = event.target.files[0];
        if (!file) return;

        // Reset state
        setUploadedFileName(file.name);
        setIsAnalyzing(true);
        setError(null);
        setAnalysisResult(null);
        setConnectionCount(0);

        try {
            // Read file
            const text = await file.text();
            
            // Parse JSON
            const connections = Utils.parseJSON(text);
            setConnectionCount(connections.length);

            // Validate data
            const validation = Utils.validateConnections(connections);
            if (!validation.isValid) {
                throw new Error(validation.errors.join('. '));
            }

            // Simulate processing time for better UX
            await new Promise(resolve => setTimeout(resolve, 1500));

            // Extract features
            const features = Analyzer.extractFeatures(connections);

            // Run detection
            const result = Detector.detect(features);

            // Get MITRE techniques
            result.mitreTechniques = Detector.getMITRETechniques(result);

            // Get feature explanations
            result.featureExplanations = Analyzer.explainFeatures(features);

            setAnalysisResult(result);

        } catch (err) {
            console.error('Analysis error:', err);
            setError(err.message);
        } finally {
            setIsAnalyzing(false);
        }
    };

    /**
     * Download analysis report as JSON
     */
    const downloadReport = () => {
        if (!analysisResult) return;
        
        const report = Utils.generateReport(analysisResult, uploadedFileName);
        const filename = `c2-analysis-${Date.now()}.json`;
        
        Utils.downloadJSON(report, filename);
    };

    /**
     * Get styling based on severity
     */
    const getSeverityStyle = (severity) => {
        const styles = {
            critical: 'bg-red-900 text-red-200 border-red-700',
            high: 'bg-orange-900 text-orange-200 border-orange-700',
            medium: 'bg-yellow-900 text-yellow-200 border-yellow-700',
            low: 'bg-blue-900 text-blue-200 border-blue-700',
            info: 'bg-green-900 text-green-200 border-green-700'
        };
        return styles[severity] || styles.info;
    };

    /**
     * Get progress bar color
     */
    const getProgressColor = (score) => {
        if (score >= 80) return 'from-red-600 to-red-500';
        if (score >= 65) return 'from-orange-600 to-orange-500';
        if (score >= 45) return 'from-yellow-600 to-yellow-500';
        if (score >= 25) return 'from-blue-600 to-blue-500';
        return 'from-green-600 to-green-500';
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
            
            {/* Header */}
            <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur">
                <div className="max-w-7xl mx-auto px-6 py-6">
                    <div className="flex items-center justify-between flex-wrap gap-4">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center">
                                <i className="fas fa-shield-alt text-2xl"></i>
                            </div>
                            <div>
                                <h1 className="text-2xl font-bold">C2 Beacon Detector</h1>
                                <p className="text-sm text-slate-400">Behavioral Network Traffic Analysis</p>
                            </div>
                        </div>
                        <a 
                            href="https://github.com/YOUR_USERNAME/c2-beacon-detector" 
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors no-print"
                        >
                            <i className="fab fa-github"></i>
                            <span>View Source</span>
                        </a>
                    </div>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-6 py-8">
                
                {/* Upload Section */}
                <section className="bg-slate-900/50 backdrop-blur rounded-xl border border-slate-800 p-8 mb-6 fade-in">
                    <div className="flex items-center gap-3 mb-6">
                        <i className="fas fa-upload text-cyan-400 text-xl"></i>
                        <h2 className="text-xl font-semibold">Upload Network Traffic Data</h2>
                    </div>
                    
                    <div className="border-2 border-dashed border-slate-700 rounded-xl p-12 text-center upload-zone cursor-pointer relative">
                        <input
                            type="file"
                            accept=".json"
                            onChange={handleFileUpload}
                            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                            id="file-upload"
                        />
                        <label htmlFor="file-upload" className="cursor-pointer">
                            <i className="fas fa-cloud-upload-alt text-6xl text-slate-600 mb-4 block"></i>
                            <p className="text-xl text-slate-300 mb-2">
                                Drop JSON file here or click to browse
                            </p>
                            <p className="text-sm text-slate-500 mb-4">
                                Accepts: Connection logs, PCAP exports (as JSON), flow data
                            </p>
                            {uploadedFileName && (
                                <div className="inline-flex items-center gap-2 bg-slate-800 px-4 py-2 rounded-lg mt-4">
                                    <i className="fas fa-file-alt text-cyan-400"></i>
                                    <span className="text-sm">{uploadedFileName}</span>
                                    {connectionCount > 0 && (
                                        <span className="text-xs text-slate-500">({connectionCount} connections)</span>
                                    )}
                                </div>
                            )}
                        </label>
                    </div>

                    {/* Format Documentation */}
                    <details className="mt-6 bg-slate-800/50 rounded-lg p-4">
                        <summary className="text-sm font-semibold text-slate-300 cursor-pointer">
                            Expected JSON Format (click to expand)
                        </summary>
                        <pre className="text-xs text-slate-400 bg-slate-950 p-3 rounded overflow-x-auto mt-3">
{`{
  "connections": [
    {
      "timestamp": 1704646800000,  // Unix epoch in milliseconds
      "bytes": 1024,                // Packet/payload size
      "dest_ip": "192.168.1.100",   // Destination IP
      "src_port": 49152,            // Source port
      "dest_port": 443              // Destination port
    },
    // ... more connections
  ]
}

Flexible field names supported:
- timestamp, time, ts, epoch (required)
- bytes, size, length, data_len
- dest_ip, dst, destination
- src_port, sport
- dest_port, dport`}
                        </pre>
                    </details>
                </section>

                {/* Error Display */}
                {error && (
                    <section className="bg-red-900/20 border-2 border-red-800 rounded-xl p-6 mb-6 fade-in">
                        <div className="flex items-start gap-3">
                            <i className="fas fa-exclamation-circle text-red-400 text-2xl mt-1"></i>
                            <div>
                                <h3 className="font-semibold text-red-300 mb-2 text-lg">Analysis Error</h3>
                                <p className="text-red-200">{error}</p>
                                <p className="text-sm text-red-300 mt-3">
                                    Check that your JSON file matches the expected format above.
                                </p>
                            </div>
                        </div>
                    </section>
                )}

                {/* Loading State */}
                {isAnalyzing && (
                    <section className="bg-slate-900/50 backdrop-blur rounded-xl border border-slate-800 p-12 text-center fade-in">
                        <div className="spinner inline-block rounded-full h-16 w-16 border-4 border-slate-700 border-t-cyan-400 mb-4"></div>
                        <p className="text-xl text-slate-300 mb-2">Analyzing behavioral patterns...</p>
                        <p className="text-sm text-slate-500">Extracting features and computing threat score</p>
                    </section>
                )}

                {/* Analysis Results */}
                {analysisResult && !isAnalyzing && (
                    <div className="space-y-6 fade-in">
                        
                        {/* Threat Score Card */}
                        <section className="bg-slate-900/50 backdrop-blur rounded-xl border border-slate-800 p-8 feature-card">
                            <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
                                <h2 className="text-2xl font-bold">Analysis Results</h2>
                                <div className="flex items-center gap-3">
                                    <span className={`px-6 py-2 rounded-full font-bold text-lg border-2 ${getSeverityStyle(analysisResult.severity)}`}>
                                        {analysisResult.classification}
                                    </span>
                                    <button
                                        onClick={downloadReport}
                                        className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-colors flex items-center gap-2 no-print"
                                        title="Download full analysis report"
                                    >
                                        <i className="fas fa-download"></i>
                                        <span>Export</span>
                                    </button>
                                </div>
                            </div>

                            {/* Threat Score Progress Bar */}
                            <div className="mb-8">
                                <div className="flex items-center justify-between mb-3">
                                    <span className="text-slate-300 text-lg">Threat Probability</span>
                                    <span className="text-5xl font-bold">{analysisResult.score}%</span>
                                </div>
                                <div className="w-full bg-slate-800 rounded-full h-6 overflow-hidden">
                                    <div
                                        className={`h-full progress-bar bg-gradient-to-r ${getProgressColor(analysisResult.score)}`}
                                        style={{ width: `${analysisResult.score}%` }}
                                    />
                                </div>
                                <div className="flex justify-between text-xs text-slate-500 mt-2">
                                    <span>0% Benign</span>
                                    <span>100% Malicious</span>
                                </div>
                            </div>

                            {/* Recommendation Box */}
                            <div className="bg-slate-800/50 rounded-lg p-6 mb-6">
                                <h3 className="font-semibold text-lg mb-3 flex items-center gap-2">
                                    <i className="fas fa-clipboard-list text-cyan-400"></i>
                                    Recommendation
                                </h3>
                                <p className="text-slate-300 leading-relaxed">{analysisResult.recommendation}</p>
                            </div>

                            {/* Detection Factors */}
                            <div className="mb-6">
                                <h3 className="font-semibold text-lg mb-4 flex items-center gap-2">
                                    <i className="fas fa-search text-cyan-400"></i>
                                    Detection Factors ({analysisResult.reasons.length})
                                </h3>
                                <div className="space-y-3">
                                    {analysisResult.reasons.map((reason, idx) => (
                                        <div key={idx} className="bg-slate-800/50 rounded-lg p-4 flex items-start gap-3 hover:bg-slate-800 transition-colors">
                                            <span className="text-slate-300 flex-1">{reason}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Technical Details */}
                            {analysisResult.technicalDetails.length > 0 && (
                                <details className="bg-slate-950/50 rounded-lg p-4">
                                    <summary className="text-sm font-semibold text-slate-400 cursor-pointer mb-2">
                                        Technical Details ({analysisResult.technicalDetails.length} items)
                                    </summary>
                                    <div className="space-y-1 mt-3">
                                        {analysisResult.technicalDetails.map((detail, idx) => (
                                            <p key={idx} className="text-xs text-slate-500 font-mono">• {detail}</p>
                                        ))}
                                    </div>
                                </details>
                            )}
                        </section>

                        {/* Framework Identification */}
                        {analysisResult.identifiedFrameworks && analysisResult.identifiedFrameworks.length > 0 && (
                            <section className="bg-slate-900/50 backdrop-blur rounded-xl border border-slate-800 p-8 feature-card">
                                <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
                                    <i className="fas fa-fingerprint text-cyan-400"></i>
                                    Potential C2 Frameworks
                                </h3>
                                <div className="grid md:grid-cols-2 gap-4">
                                    {analysisResult.identifiedFrameworks.map((framework, idx) => (
                                        <div key={idx} className="bg-slate-800/50 rounded-lg p-4">
                                            <div className="flex items-center justify-between mb-2">
                                                <span className="font-bold text-lg">{framework.name}</span>
                                                <span className={`text-xs px-2 py-1 rounded ${
                                                    framework.confidence === 'High' ? 'bg-red-900 text-red-200' :
                                                    framework.confidence === 'Medium' ? 'bg-yellow-900 text-yellow-200' :
                                                    'bg-blue-900 text-blue-200'
                                                }`}>
                                                    {framework.confidence}
                                                </span>
                                            </div>
                                            <p className="text-sm text-slate-400">{framework.reason}</p>
                                        </div>
                                    ))}
                                </div>
                            </section>
                        )}

                        {/* MITRE ATT&CK Mapping */}
                        {analysisResult.mitreTechniques && analysisResult.mitreTechniques.length > 0 && (
                            <section className="bg-slate-900/50 backdrop-blur rounded-xl border border-slate-800 p-8 feature-card">
                                <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
                                    <i className="fas fa-shield-virus text-cyan-400"></i>
                                    MITRE ATT&CK Techniques
                                </h3>
                                <div className="grid md:grid-cols-2 gap-4">
                                    {analysisResult.mitreTechniques.map((technique, idx) => (
                                        <div key={idx} className="bg-slate-800/50 rounded-lg p-4 hover:bg-slate-800 transition-colors">
                                            <div className="flex items-start justify-between gap-2 mb-2">
                                                <span className="font-mono text-sm text-cyan-400">{technique.id}</span>
                                                <span className="text-xs text-slate-500">{technique.tactic}</span>
                                            </div>
                                            <p className="text-sm text-slate-300">{technique.name}</p>
                                        </div>
                                    ))}
                                </div>
                            </section>
                        )}

                        {/* Feature Matrix */}
                        <section className="bg-slate-900/50 backdrop-blur rounded-xl border border-slate-800 p-8 feature-card">
                            <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
                                <i className="fas fa-chart-line text-cyan-400"></i>
                                Extracted Features
                            </h3>
                            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 feature-grid">
                                {Object.entries(analysisResult.features).map(([key, value]) => (
                                    <div key={key} className="bg-slate-800/50 rounded-lg p-4 hover:bg-slate-800 transition-colors">
                                        <div className="text-xs text-slate-400 mb-1 uppercase tracking-wide">
                                            {key.replace(/_/g, ' ')}
                                        </div>
                                        <div className="text-2xl font-bold text-cyan-400">
                                            {typeof value === 'number' ? 
                                                value < 1 && value > 0 ? value.toFixed(4) : value.toFixed(2)
                                                : value}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </section>

                        {/* Feature Explanations */}
                        {analysisResult.featureExplanations && analysisResult.featureExplanations.length > 0 && (
                            <section className="bg-slate-900/50 backdrop-blur rounded-xl border border-slate-800 p-8 feature-card">
                                <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
                                    <i className="fas fa-lightbulb text-cyan-
